rule TTP_XOR_MULT_DOSStub_6057 {
  strings:
    $key_6057 = { 34 3f [2] 40 27 [2] 07 25 [2] 40 34 [2] 0e 38 [2] 02 32 [2] 15 39 [2] 0e 77 [2] 33 }

  condition:
    any of them
}