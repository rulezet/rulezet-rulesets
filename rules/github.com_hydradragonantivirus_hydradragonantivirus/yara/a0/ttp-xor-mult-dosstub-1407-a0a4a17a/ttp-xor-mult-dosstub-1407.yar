rule TTP_XOR_MULT_DOSStub_1407 {
  strings:
    $key_1407 = { 40 6f [2] 34 77 [2] 73 75 [2] 34 64 [2] 7a 68 [2] 76 62 [2] 61 69 [2] 7a 27 [2] 47 }

  condition:
    any of them
}