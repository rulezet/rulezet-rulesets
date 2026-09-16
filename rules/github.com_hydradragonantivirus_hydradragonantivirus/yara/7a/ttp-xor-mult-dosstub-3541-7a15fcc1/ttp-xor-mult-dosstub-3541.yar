rule TTP_XOR_MULT_DOSStub_3541 {
  strings:
    $key_3541 = { 61 29 [2] 15 31 [2] 52 33 [2] 15 22 [2] 5b 2e [2] 57 24 [2] 40 2f [2] 5b 61 [2] 66 }

  condition:
    any of them
}