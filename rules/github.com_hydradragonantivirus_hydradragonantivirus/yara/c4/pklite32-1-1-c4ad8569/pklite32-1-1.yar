import "pe"
rule PKLITE32_1_1 {
  strings:
    $a0 = "PKLITE32 Copyright 1"

  condition:
    $a0 at pe.entry_point
}