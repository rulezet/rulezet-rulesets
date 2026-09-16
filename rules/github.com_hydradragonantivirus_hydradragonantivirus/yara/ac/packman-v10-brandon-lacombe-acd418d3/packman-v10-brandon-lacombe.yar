import "pe"
rule _Packman_V10__Brandon_LaCombe_ {
  meta:
    description = "Packman V1.0 -> Brandon LaCombe"

  strings:
    $0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA }

  condition:
    $0 at pe.entry_point
}