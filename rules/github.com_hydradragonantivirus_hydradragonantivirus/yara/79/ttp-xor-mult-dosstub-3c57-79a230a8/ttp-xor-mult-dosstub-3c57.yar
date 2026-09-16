rule TTP_XOR_MULT_DOSStub_3c57 {
  strings:
    $key_3c57 = { 68 3f [2] 1c 27 [2] 5b 25 [2] 1c 34 [2] 52 38 [2] 5e 32 [2] 49 39 [2] 52 77 [2] 6f }

  condition:
    any of them
}