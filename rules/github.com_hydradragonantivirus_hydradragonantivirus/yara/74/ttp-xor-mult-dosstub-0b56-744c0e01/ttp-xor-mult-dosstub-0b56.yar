rule TTP_XOR_MULT_DOSStub_0b56 {
  strings:
    $key_0b56 = { 5f 3e [2] 2b 26 [2] 6c 24 [2] 2b 35 [2] 65 39 [2] 69 33 [2] 7e 38 [2] 65 76 [2] 58 }

  condition:
    any of them
}