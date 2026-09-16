rule TTP_XOR_MULT_DOSStub_5820 {
  strings:
    $key_5820 = { 0c 48 [2] 78 50 [2] 3f 52 [2] 78 43 [2] 36 4f [2] 3a 45 [2] 2d 4e [2] 36 00 [2] 0b }

  condition:
    any of them
}