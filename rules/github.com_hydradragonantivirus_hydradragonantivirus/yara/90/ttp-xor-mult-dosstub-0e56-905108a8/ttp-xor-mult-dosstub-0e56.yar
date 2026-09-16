rule TTP_XOR_MULT_DOSStub_0e56 {
  strings:
    $key_0e56 = { 5a 3e [2] 2e 26 [2] 69 24 [2] 2e 35 [2] 60 39 [2] 6c 33 [2] 7b 38 [2] 60 76 [2] 5d }

  condition:
    any of them
}