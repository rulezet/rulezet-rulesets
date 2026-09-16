rule TTP_XOR_MULT_DOSStub_4c59 {
  strings:
    $key_4c59 = { 18 31 [2] 6c 29 [2] 2b 2b [2] 6c 3a [2] 22 36 [2] 2e 3c [2] 39 37 [2] 22 79 [2] 1f }

  condition:
    any of them
}