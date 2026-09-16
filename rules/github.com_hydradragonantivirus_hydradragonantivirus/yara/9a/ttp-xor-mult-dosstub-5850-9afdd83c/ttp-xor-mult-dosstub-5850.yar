rule TTP_XOR_MULT_DOSStub_5850 {
  strings:
    $key_5850 = { 0c 38 [2] 78 20 [2] 3f 22 [2] 78 33 [2] 36 3f [2] 3a 35 [2] 2d 3e [2] 36 70 [2] 0b }

  condition:
    any of them
}