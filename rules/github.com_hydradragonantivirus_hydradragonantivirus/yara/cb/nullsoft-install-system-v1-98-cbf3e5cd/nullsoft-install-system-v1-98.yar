import "pe"
rule Nullsoft_Install_System_v1_98 {
  strings:
    $a0 = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }

  condition:
    $a0 at pe.entry_point
}