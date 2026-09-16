rule TTP_XOR_MULT_DOSStub_4946 {
  strings:
    $key_4946 = { 1d 2e [2] 69 36 [2] 2e 34 [2] 69 25 [2] 27 29 [2] 2b 23 [2] 3c 28 [2] 27 66 [2] 1a }

  condition:
    any of them
}