rule TTP_XOR_MULT_DOSStub_5836 {
  strings:
    $key_5836 = { 0c 5e [2] 78 46 [2] 3f 44 [2] 78 55 [2] 36 59 [2] 3a 53 [2] 2d 58 [2] 36 16 [2] 0b }

  condition:
    any of them
}