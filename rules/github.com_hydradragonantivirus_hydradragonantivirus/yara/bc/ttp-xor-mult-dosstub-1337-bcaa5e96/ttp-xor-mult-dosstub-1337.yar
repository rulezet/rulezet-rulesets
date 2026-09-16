rule TTP_XOR_MULT_DOSStub_1337 {
  strings:
    $key_1337 = { 47 5f [2] 33 47 [2] 74 45 [2] 33 54 [2] 7d 58 [2] 71 52 [2] 66 59 [2] 7d 17 [2] 40 }

  condition:
    any of them
}