rule TTP_XOR_MULT_DOSStub_1456 {
  strings:
    $key_1456 = { 40 3e [2] 34 26 [2] 73 24 [2] 34 35 [2] 7a 39 [2] 76 33 [2] 61 38 [2] 7a 76 [2] 47 }

  condition:
    any of them
}