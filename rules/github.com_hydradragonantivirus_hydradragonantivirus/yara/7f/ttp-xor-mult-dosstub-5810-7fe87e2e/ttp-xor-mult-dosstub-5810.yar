rule TTP_XOR_MULT_DOSStub_5810 {
  strings:
    $key_5810 = { 0c 78 [2] 78 60 [2] 3f 62 [2] 78 73 [2] 36 7f [2] 3a 75 [2] 2d 7e [2] 36 30 [2] 0b }

  condition:
    any of them
}