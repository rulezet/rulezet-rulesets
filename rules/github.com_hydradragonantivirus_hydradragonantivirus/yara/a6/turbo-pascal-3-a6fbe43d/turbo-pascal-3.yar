import "pe"
rule _Turbo_Pascal_3_ {
  meta:
    description = "Turbo Pascal 3"

  strings:
    $0 = { E9 00 00 90 90 CD AB 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 31 39 38 35 20 42 4F 52 4C 41 4E 44 20 49 6E 63 02 04 00 }

  condition:
    $0 at pe.entry_point
}