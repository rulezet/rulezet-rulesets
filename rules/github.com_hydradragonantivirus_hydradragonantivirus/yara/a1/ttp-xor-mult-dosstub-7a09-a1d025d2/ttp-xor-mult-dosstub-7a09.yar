rule TTP_XOR_MULT_DOSStub_7a09 {
  strings:
    $key_7a09 = { 2e 61 [2] 5a 79 [2] 1d 7b [2] 5a 6a [2] 14 66 [2] 18 6c [2] 0f 67 [2] 14 29 [2] 29 }

  condition:
    any of them
}