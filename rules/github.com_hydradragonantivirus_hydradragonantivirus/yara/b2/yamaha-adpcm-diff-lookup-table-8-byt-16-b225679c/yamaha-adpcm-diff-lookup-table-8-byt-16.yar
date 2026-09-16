rule Yamaha_ADPCM_diff_lookup_table__8_byt_16_ {
  strings:
    $a0 = { 01 03 05 07 09 0B 0D 0F FF FD FB F9 F7 F5 F3 F1 }

  condition:
    $a0
}