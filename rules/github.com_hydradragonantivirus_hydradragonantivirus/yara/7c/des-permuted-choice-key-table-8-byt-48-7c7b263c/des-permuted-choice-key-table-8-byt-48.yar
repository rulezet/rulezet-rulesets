rule DES_permuted_choice_key__table___8_byt_48_ {
  strings:
    $a0 = { 0e 11 0b 18 01 05 03 1c 0f 06 15 0a 17 13 0c 04 1a 08 10 07 1b 14 0d 02 29 34 1f 25 2f 37 1e 28 33 2d 21 30 2c 31 27 38 22 35 2e 2a 32 24 1d 20 }

  condition:
    $a0
}