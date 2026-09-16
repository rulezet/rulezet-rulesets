rule TTP_XOR_MULT_DOSStub_4541 {
  strings:
    $key_4541 = { 11 29 [2] 65 31 [2] 22 33 [2] 65 22 [2] 2b 2e [2] 27 24 [2] 30 2f [2] 2b 61 [2] 16 }

  condition:
    any of them
}