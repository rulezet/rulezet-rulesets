import "pe"
rule visual_c_plus_plus_6: Compiler {
  meta:
    author      = "Kevin Falcoz"
    date_create = "25/02/2013"
    description = "Miscrosoft Visual C++ 6.0"

  strings:
    $str1 = { 55 8B EC 6A FF 68 [3] 00 68 [3] 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC [1] 53 56 57 89 65 E8 }  

  condition:
    $str1 at (pe.entry_point)
}