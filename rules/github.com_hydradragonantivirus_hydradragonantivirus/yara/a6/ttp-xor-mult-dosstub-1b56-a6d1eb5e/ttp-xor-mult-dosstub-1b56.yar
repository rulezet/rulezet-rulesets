rule TTP_XOR_MULT_DOSStub_1b56 {
  strings:
    $key_1b56 = { 4f 3e [2] 3b 26 [2] 7c 24 [2] 3b 35 [2] 75 39 [2] 79 33 [2] 6e 38 [2] 75 76 [2] 48 }

  condition:
    any of them
}