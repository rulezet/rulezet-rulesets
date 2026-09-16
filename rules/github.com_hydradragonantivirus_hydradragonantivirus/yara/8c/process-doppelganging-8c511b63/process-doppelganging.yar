import "pe"
rule Process_Doppelganging
{
    meta:
        author = "McAfee ATR - Thomas Roccia - @fr0gger_"
        description = "Detect Process Doppelganging"
        reference = "https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf"
        mitre_id = "T1186"
    strings:
        $func1 = "CreateTransaction" nocase
        $func2 = "CreateFileTransacted" nocase
        $func3 = "WriteFile" nocase
        $func5 = "RollbackTransaction" nocase
        $func6 = "CreateProcess" nocase
        $func7 = "CreateProcessParameters"
    condition:
        uint16(0) == 0x5A4D and ($func1 or $func2 or $func5 or (all of them) or
        pe.imports("KtmW32.dll", "CreateTransaction") and
        pe.imports("Kernel32.dll", "CreateFileTransacted") and
        pe.imports("KtmW32.dll", "RollbackTransaction"))
}