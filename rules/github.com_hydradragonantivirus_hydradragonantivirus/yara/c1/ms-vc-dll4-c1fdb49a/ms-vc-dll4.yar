import "pe"
rule ms_vc_dll4 {
  meta:
    author      = "PEiD"
    description = "Microsoft Visual C++ DLL Method 4"
    group       = "15"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 56 57 BF 01 ?? ?? ?? 8B 75 0C }

  condition:
    $a0 at pe.entry_point
}