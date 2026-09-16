rule TTP_XOR_MULT_DOSStub_0e76 {
  strings:
    $key_0e76 = { 5a 1e [2] 2e 06 [2] 69 04 [2] 2e 15 [2] 60 19 [2] 6c 13 [2] 7b 18 [2] 60 56 [2] 5d }

  condition:
    any of them
}