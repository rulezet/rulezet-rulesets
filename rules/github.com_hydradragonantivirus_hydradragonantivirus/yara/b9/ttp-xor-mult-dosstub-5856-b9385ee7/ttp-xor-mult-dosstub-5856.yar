rule TTP_XOR_MULT_DOSStub_5856 {
  strings:
    $key_5856 = { 0c 3e [2] 78 26 [2] 3f 24 [2] 78 35 [2] 36 39 [2] 3a 33 [2] 2d 38 [2] 36 76 [2] 0b }

  condition:
    any of them
}