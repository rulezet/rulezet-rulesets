import "pe"
rule ms_vc8_h2 {
  meta:
    author      = "PEiD"
    description = "Microsoft Visual C++ 8.0 DLL"
    group       = "BoB"
    function    = "0"

  strings:
    $a0 = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 ?? ?? 00 00 83 FE 01 }

  condition:
    $a0 at pe.entry_point
}