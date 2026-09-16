rule TTP_XOR_MULT_DOSStub_4147 {
  strings:
    $key_4147 = { 15 2f [2] 61 37 [2] 26 35 [2] 61 24 [2] 2f 28 [2] 23 22 [2] 34 29 [2] 2f 67 [2] 12 }

  condition:
    any of them
}