rule TTP_XOR_MULT_DOSStub_0b57 {
  strings:
    $key_0b57 = { 5f 3f [2] 2b 27 [2] 6c 25 [2] 2b 34 [2] 65 38 [2] 69 32 [2] 7e 39 [2] 65 77 [2] 58 }

  condition:
    any of them
}