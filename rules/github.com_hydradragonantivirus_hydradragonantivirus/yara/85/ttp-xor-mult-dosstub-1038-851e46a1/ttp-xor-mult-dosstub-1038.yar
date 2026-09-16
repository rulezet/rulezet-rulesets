rule TTP_XOR_MULT_DOSStub_1038 {
  strings:
    $key_1038 = { 44 50 [2] 30 48 [2] 77 4a [2] 30 5b [2] 7e 57 [2] 72 5d [2] 65 56 [2] 7e 18 [2] 43 }

  condition:
    any of them
}