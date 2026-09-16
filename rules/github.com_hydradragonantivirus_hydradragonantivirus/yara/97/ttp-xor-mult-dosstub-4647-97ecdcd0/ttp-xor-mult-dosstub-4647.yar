rule TTP_XOR_MULT_DOSStub_4647 {
  strings:
    $key_4647 = { 12 2f [2] 66 37 [2] 21 35 [2] 66 24 [2] 28 28 [2] 24 22 [2] 33 29 [2] 28 67 [2] 15 }

  condition:
    any of them
}