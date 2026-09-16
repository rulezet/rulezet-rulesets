rule TTP_XOR_MULT_DOSStub_3139 {
  strings:
    $key_3139 = { 65 51 [2] 11 49 [2] 56 4b [2] 11 5a [2] 5f 56 [2] 53 5c [2] 44 57 [2] 5f 19 [2] 62 }

  condition:
    any of them
}