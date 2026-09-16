rule DES_permuted_choice_table__key___8_byt_56_ {
  strings:
    $a0 = { 39 31 29 21 19 11 09 01 3a 32 2a 22 1a 12 0a 02 3b 33 2b 23 1b 13 0b 03 3c 34 2c 24 3f 37 2f 27 1f 17 0f 07 3e 36 2e 26 1e 16 0e 06 3d 35 2d 25 1d 15 0d 05 1c 14 0c 04 }

  condition:
    $a0
}