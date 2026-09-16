rule TTP_XOR_MULT_DOSStub_2a70 {
  strings:
    $key_2a70 = { 7e 18 [2] 0a 00 [2] 4d 02 [2] 0a 13 [2] 44 1f [2] 48 15 [2] 5f 1e [2] 44 50 [2] 79 }

  condition:
    any of them
}