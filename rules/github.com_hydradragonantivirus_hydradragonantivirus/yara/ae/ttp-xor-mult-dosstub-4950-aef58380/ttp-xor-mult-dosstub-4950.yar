rule TTP_XOR_MULT_DOSStub_4950 {
  strings:
    $key_4950 = { 1d 38 [2] 69 20 [2] 2e 22 [2] 69 33 [2] 27 3f [2] 2b 35 [2] 3c 3e [2] 27 70 [2] 1a }

  condition:
    any of them
}