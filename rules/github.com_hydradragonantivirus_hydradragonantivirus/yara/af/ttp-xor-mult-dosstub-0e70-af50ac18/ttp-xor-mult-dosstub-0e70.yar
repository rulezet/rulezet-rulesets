rule TTP_XOR_MULT_DOSStub_0e70 {
  strings:
    $key_0e70 = { 5a 18 [2] 2e 00 [2] 69 02 [2] 2e 13 [2] 60 1f [2] 6c 15 [2] 7b 1e [2] 60 50 [2] 5d }

  condition:
    any of them
}