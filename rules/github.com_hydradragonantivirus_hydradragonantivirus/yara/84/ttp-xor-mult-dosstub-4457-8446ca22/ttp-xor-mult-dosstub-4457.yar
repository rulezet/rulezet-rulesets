rule TTP_XOR_MULT_DOSStub_4457 {
  strings:
    $key_4457 = { 10 3f [2] 64 27 [2] 23 25 [2] 64 34 [2] 2a 38 [2] 26 32 [2] 31 39 [2] 2a 77 [2] 17 }

  condition:
    any of them
}