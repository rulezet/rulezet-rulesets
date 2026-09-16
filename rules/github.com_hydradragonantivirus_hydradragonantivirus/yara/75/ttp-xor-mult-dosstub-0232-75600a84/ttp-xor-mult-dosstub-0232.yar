rule TTP_XOR_MULT_DOSStub_0232 {
  strings:
    $key_0232 = { 56 5a [2] 22 42 [2] 65 40 [2] 22 51 [2] 6c 5d [2] 60 57 [2] 77 5c [2] 6c 12 [2] 51 }

  condition:
    any of them
}