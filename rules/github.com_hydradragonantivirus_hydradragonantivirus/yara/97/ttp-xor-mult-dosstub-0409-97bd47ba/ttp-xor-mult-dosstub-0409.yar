rule TTP_XOR_MULT_DOSStub_0409 {
  strings:
    $key_0409 = { 50 61 [2] 24 79 [2] 63 7b [2] 24 6a [2] 6a 66 [2] 66 6c [2] 71 67 [2] 6a 29 [2] 57 }

  condition:
    any of them
}