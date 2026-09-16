import "pe"
rule SuckStop_v1_11 {
  strings:
    $a0 = { EB ?? ?? ?? BE ?? ?? B4 30 CD 21 EB ?? 9B }

  condition:
    $a0 at pe.entry_point
}