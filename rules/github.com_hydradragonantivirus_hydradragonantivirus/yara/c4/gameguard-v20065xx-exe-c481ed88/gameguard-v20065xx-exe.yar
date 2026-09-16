import "pe"
rule _GameGuard_v20065xx_exe_ {
  meta:
    description = "GameGuard v2006.5.x.x (*.exe)"

  strings:
    $0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }
    $1 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}