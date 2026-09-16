rule TTP_XOR_MULT_DOSStub_4930 {
  strings:
    $key_4930 = { 1d 58 [2] 69 40 [2] 2e 42 [2] 69 53 [2] 27 5f [2] 2b 55 [2] 3c 5e [2] 27 10 [2] 1a }

  condition:
    any of them
}