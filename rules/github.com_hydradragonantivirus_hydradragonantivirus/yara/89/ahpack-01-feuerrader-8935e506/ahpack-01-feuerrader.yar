import "pe"
rule _AHpack_01__FEUERRADER_ {
  meta:
    description = "AHpack 0.1 -> FEUERRADER"

  strings:
    $0 = { 60 68 54 ?? ?? ?? B8 48 ?? ?? ?? FF 10 68 B3 ?? ?? ?? 50 B8 44 ?? ?? ?? FF 10 68 00 ?? ?? ?? 6A 40 FF D0 89 05 CA ?? ?? ?? 89 C7 BE 00 10 ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 }

  condition:
    $0 at pe.entry_point
}