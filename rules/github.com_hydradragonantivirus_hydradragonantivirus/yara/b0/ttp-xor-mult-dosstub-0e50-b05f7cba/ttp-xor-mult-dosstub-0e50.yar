rule TTP_XOR_MULT_DOSStub_0e50 {
  strings:
    $key_0e50 = { 5a 38 [2] 2e 20 [2] 69 22 [2] 2e 33 [2] 60 3f [2] 6c 35 [2] 7b 3e [2] 60 70 [2] 5d }

  condition:
    any of them
}