import "pe"
rule AcidCrypt_ren: Packer {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 60 B9 ?? ?? ?? 00 BA ?? ?? ?? 00 BE ?? ?? ?? 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
    $a1 = { BE ?? ?? ?? ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}