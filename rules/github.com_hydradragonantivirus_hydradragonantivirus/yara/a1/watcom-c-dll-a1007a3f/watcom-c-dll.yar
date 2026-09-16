import "pe"
rule watcom_c_dll {
  meta:
    author      = "PEiD"
    description = "Watcom C/C++ DLL"
    group       = "17"
    function    = "0"

  strings:
    $a0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 }

  condition:
    $a0 at pe.entry_point
}