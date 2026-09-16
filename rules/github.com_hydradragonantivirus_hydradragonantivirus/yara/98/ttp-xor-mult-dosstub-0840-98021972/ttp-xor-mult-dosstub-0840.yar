rule TTP_XOR_MULT_DOSStub_0840 {
  strings:
    $key_0840 = { 5c 28 [2] 28 30 [2] 6f 32 [2] 28 23 [2] 66 2f [2] 6a 25 [2] 7d 2e [2] 66 60 [2] 5b }

  condition:
    any of them
}