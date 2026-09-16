import "pe"
rule _PE_Diminisher_V01__Teraphy_ {
  meta:
    description = "PE Diminisher V0.1 -> Teraphy"

  strings:
    $0 = { 53 51 52 56 57 55 E8 00 00 00 00 }

  condition:
    $0 at pe.entry_point
}