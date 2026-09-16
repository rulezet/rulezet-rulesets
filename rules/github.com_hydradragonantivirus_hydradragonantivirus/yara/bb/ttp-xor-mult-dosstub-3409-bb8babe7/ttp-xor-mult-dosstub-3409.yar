rule TTP_XOR_MULT_DOSStub_3409 {
  strings:
    $key_3409 = { 60 61 [2] 14 79 [2] 53 7b [2] 14 6a [2] 5a 66 [2] 56 6c [2] 41 67 [2] 5a 29 [2] 67 }

  condition:
    any of them
}