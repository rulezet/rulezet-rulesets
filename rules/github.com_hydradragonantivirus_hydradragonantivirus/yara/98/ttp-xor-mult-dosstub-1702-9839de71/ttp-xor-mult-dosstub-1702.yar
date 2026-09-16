rule TTP_XOR_MULT_DOSStub_1702 {
  strings:
    $key_1702 = { 43 6a [2] 37 72 [2] 70 70 [2] 37 61 [2] 79 6d [2] 75 67 [2] 62 6c [2] 79 22 [2] 44 }

  condition:
    any of them
}