rule TTP_XOR_MULT_DOSStub_7070 {
  strings:
    $key_7070 = { 24 18 [2] 50 00 [2] 17 02 [2] 50 13 [2] 1e 1f [2] 12 15 [2] 05 1e [2] 1e 50 [2] 23 }

  condition:
    any of them
}