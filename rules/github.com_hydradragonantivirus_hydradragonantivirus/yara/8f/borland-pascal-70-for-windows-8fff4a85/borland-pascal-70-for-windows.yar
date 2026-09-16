import "pe"
rule _Borland_Pascal_70_for_Windows_ {
  meta:
    description = "Borland Pascal 7.0 for Windows"

  strings:
    $0 = { 9A FF FF 00 00 9A FF FF 00 00 55 89 E5 31 C0 9A FF FF 00 00 }

  condition:
    $0 at pe.entry_point
}