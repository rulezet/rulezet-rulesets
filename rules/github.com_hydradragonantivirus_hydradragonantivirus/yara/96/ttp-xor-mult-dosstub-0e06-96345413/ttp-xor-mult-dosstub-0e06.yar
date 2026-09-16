rule TTP_XOR_MULT_DOSStub_0e06 {
  strings:
    $key_0e06 = { 5a 6e [2] 2e 76 [2] 69 74 [2] 2e 65 [2] 60 69 [2] 6c 63 [2] 7b 68 [2] 60 26 [2] 5d }

  condition:
    any of them
}