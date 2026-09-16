rule TTP_XOR_MULT_DOSStub_5c57 {
  strings:
    $key_5c57 = { 08 3f [2] 7c 27 [2] 3b 25 [2] 7c 34 [2] 32 38 [2] 3e 32 [2] 29 39 [2] 32 77 [2] 0f }

  condition:
    any of them
}