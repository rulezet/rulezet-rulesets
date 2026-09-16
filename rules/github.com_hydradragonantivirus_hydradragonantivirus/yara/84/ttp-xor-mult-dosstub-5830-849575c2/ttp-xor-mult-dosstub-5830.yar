rule TTP_XOR_MULT_DOSStub_5830 {
  strings:
    $key_5830 = { 0c 58 [2] 78 40 [2] 3f 42 [2] 78 53 [2] 36 5f [2] 3a 55 [2] 2d 5e [2] 36 10 [2] 0b }

  condition:
    any of them
}