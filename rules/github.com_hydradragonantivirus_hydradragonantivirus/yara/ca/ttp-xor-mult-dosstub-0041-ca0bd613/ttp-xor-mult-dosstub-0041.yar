rule TTP_XOR_MULT_DOSStub_0041 {
  strings:
    $key_0041 = { 54 29 [2] 20 31 [2] 67 33 [2] 20 22 [2] 6e 2e [2] 62 24 [2] 75 2f [2] 6e 61 [2] 53 }

  condition:
    any of them
}