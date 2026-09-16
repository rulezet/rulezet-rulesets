rule TTP_XOR_MULT_DOSStub_fbb7 {
  strings:
    $key_fbb7 = { af df [2] db c7 [2] 9c c5 [2] db d4 [2] 95 d8 [2] 99 d2 [2] 8e d9 [2] 95 97 [2] a8 }

  condition:
    any of them
}