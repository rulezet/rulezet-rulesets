rule TTP_XOR_MULT_DOSStub_0204 {
  strings:
    $key_0204 = { 56 6c [2] 22 74 [2] 65 76 [2] 22 67 [2] 6c 6b [2] 60 61 [2] 77 6a [2] 6c 24 [2] 51 }

  condition:
    any of them
}