rule TTP_XOR_MULT_DOSStub_3530 {
  strings:
    $key_3530 = { 61 58 [2] 15 40 [2] 52 42 [2] 15 53 [2] 5b 5f [2] 57 55 [2] 40 5e [2] 5b 10 [2] 66 }

  condition:
    any of them
}