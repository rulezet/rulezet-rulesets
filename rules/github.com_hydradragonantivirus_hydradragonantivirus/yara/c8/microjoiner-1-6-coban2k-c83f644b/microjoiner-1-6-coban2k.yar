import "pe"
rule MicroJoiner_1_6____coban2k {
  strings:
    $a0 = { 33 C0 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B }

  condition:
    $a0 at pe.entry_point
}