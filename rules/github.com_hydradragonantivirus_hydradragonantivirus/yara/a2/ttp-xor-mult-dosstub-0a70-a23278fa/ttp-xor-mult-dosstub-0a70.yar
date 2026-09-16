rule TTP_XOR_MULT_DOSStub_0a70 {
  strings:
    $key_0a70 = { 5e 18 [2] 2a 00 [2] 6d 02 [2] 2a 13 [2] 64 1f [2] 68 15 [2] 7f 1e [2] 64 50 [2] 59 }

  condition:
    any of them
}