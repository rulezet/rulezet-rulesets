rule TTP_XOR_MULT_DOSStub_0215 {
  strings:
    $key_0215 = { 56 7d [2] 22 65 [2] 65 67 [2] 22 76 [2] 6c 7a [2] 60 70 [2] 77 7b [2] 6c 35 [2] 51 }

  condition:
    any of them
}