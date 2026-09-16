rule TTP_XOR_MULT_DOSStub_3118 {
  strings:
    $key_3118 = { 65 70 [2] 11 68 [2] 56 6a [2] 11 7b [2] 5f 77 [2] 53 7d [2] 44 76 [2] 5f 38 [2] 62 }

  condition:
    any of them
}