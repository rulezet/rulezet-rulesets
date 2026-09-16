rule TTP_XOR_MULT_DOSStub_0e47 {
  strings:
    $key_0e47 = { 5a 2f [2] 2e 37 [2] 69 35 [2] 2e 24 [2] 60 28 [2] 6c 22 [2] 7b 29 [2] 60 67 [2] 5d }

  condition:
    any of them
}