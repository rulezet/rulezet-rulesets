rule TTP_XOR_MULT_DOSStub_3107 {
  strings:
    $key_3107 = { 65 6f [2] 11 77 [2] 56 75 [2] 11 64 [2] 5f 68 [2] 53 62 [2] 44 69 [2] 5f 27 [2] 62 }

  condition:
    any of them
}