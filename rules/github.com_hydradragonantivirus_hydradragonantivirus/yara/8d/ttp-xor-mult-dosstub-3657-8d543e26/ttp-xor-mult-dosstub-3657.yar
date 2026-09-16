rule TTP_XOR_MULT_DOSStub_3657 {
  strings:
    $key_3657 = { 62 3f [2] 16 27 [2] 51 25 [2] 16 34 [2] 58 38 [2] 54 32 [2] 43 39 [2] 58 77 [2] 65 }

  condition:
    any of them
}