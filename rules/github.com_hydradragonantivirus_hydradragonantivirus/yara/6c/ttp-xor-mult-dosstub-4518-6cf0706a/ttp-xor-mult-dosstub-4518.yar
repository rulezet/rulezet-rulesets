rule TTP_XOR_MULT_DOSStub_4518 {
  strings:
    $key_4518 = { 11 70 [2] 65 68 [2] 22 6a [2] 65 7b [2] 2b 77 [2] 27 7d [2] 30 76 [2] 2b 38 [2] 16 }

  condition:
    any of them
}