import "pe"
rule _PIRIT_v15_ {
  meta:
    description = "$PIRIT v1.5"

  strings:
    $0 = { B4 4D CD 21 E8 ?? ?? FD E8 ?? ?? B4 51 CD 21 }

  condition:
    $0 at pe.entry_point
}