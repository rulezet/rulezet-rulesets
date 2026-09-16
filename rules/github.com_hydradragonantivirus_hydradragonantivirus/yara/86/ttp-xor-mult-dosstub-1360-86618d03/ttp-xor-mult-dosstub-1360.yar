rule TTP_XOR_MULT_DOSStub_1360 {
  strings:
    $key_1360 = { 47 08 [2] 33 10 [2] 74 12 [2] 33 03 [2] 7d 0f [2] 71 05 [2] 66 0e [2] 7d 40 [2] 40 }

  condition:
    any of them
}