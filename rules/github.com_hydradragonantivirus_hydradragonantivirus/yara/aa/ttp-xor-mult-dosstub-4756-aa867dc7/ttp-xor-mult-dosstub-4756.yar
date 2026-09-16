rule TTP_XOR_MULT_DOSStub_4756 {
  strings:
    $key_4756 = { 13 3e [2] 67 26 [2] 20 24 [2] 67 35 [2] 29 39 [2] 25 33 [2] 32 38 [2] 29 76 [2] 14 }

  condition:
    any of them
}