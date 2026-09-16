rule TTP_XOR_MULT_DOSStub_7257 {
  strings:
    $key_7257 = { 26 3f [2] 52 27 [2] 15 25 [2] 52 34 [2] 1c 38 [2] 10 32 [2] 07 39 [2] 1c 77 [2] 21 }

  condition:
    any of them
}