rule TTP_XOR_MULT_DOSStub_4c09 {
  strings:
    $key_4c09 = { 18 61 [2] 6c 79 [2] 2b 7b [2] 6c 6a [2] 22 66 [2] 2e 6c [2] 39 67 [2] 22 29 [2] 1f }

  condition:
    any of them
}