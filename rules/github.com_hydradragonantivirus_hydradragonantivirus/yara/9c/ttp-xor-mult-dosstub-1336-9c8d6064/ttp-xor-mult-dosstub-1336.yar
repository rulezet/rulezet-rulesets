rule TTP_XOR_MULT_DOSStub_1336 {
  strings:
    $key_1336 = { 47 5e [2] 33 46 [2] 74 44 [2] 33 55 [2] 7d 59 [2] 71 53 [2] 66 58 [2] 7d 16 [2] 40 }

  condition:
    any of them
}