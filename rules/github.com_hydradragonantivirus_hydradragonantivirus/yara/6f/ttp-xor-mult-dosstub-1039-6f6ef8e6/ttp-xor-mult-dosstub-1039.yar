rule TTP_XOR_MULT_DOSStub_1039 {
  strings:
    $key_1039 = { 44 51 [2] 30 49 [2] 77 4b [2] 30 5a [2] 7e 56 [2] 72 5c [2] 65 57 [2] 7e 19 [2] 43 }

  condition:
    any of them
}