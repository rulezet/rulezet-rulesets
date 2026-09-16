rule TTP_XOR_MULT_DOSStub_1002 {
  strings:
    $key_1002 = { 44 6a [2] 30 72 [2] 77 70 [2] 30 61 [2] 7e 6d [2] 72 67 [2] 65 6c [2] 7e 22 [2] 43 }

  condition:
    any of them
}