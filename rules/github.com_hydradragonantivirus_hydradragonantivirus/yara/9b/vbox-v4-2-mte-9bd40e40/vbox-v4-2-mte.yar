import "pe"
rule VBOX_v4_2_MTE {
  strings:
    $a0 = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5 }

  condition:
    $a0 at pe.entry_point
}