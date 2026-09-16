rule TTP_XOR_MULT_DOSStub_4921 {
  strings:
    $key_4921 = { 1d 49 [2] 69 51 [2] 2e 53 [2] 69 42 [2] 27 4e [2] 2b 44 [2] 3c 4f [2] 27 01 [2] 1a }

  condition:
    any of them
}