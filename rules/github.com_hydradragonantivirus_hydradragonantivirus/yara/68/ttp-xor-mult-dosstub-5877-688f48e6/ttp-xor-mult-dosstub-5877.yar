rule TTP_XOR_MULT_DOSStub_5877 {
  strings:
    $key_5877 = { 0c 1f [2] 78 07 [2] 3f 05 [2] 78 14 [2] 36 18 [2] 3a 12 [2] 2d 19 [2] 36 57 [2] 0b }

  condition:
    any of them
}