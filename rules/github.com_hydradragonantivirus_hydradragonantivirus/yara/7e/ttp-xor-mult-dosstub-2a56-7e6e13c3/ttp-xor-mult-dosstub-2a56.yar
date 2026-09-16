rule TTP_XOR_MULT_DOSStub_2a56 {
  strings:
    $key_2a56 = { 7e 3e [2] 0a 26 [2] 4d 24 [2] 0a 35 [2] 44 39 [2] 48 33 [2] 5f 38 [2] 44 76 [2] 79 }

  condition:
    any of them
}