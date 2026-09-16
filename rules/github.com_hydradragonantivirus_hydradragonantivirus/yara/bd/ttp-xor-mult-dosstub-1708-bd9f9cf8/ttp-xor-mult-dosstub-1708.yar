rule TTP_XOR_MULT_DOSStub_1708 {
  strings:
    $key_1708 = { 43 60 [2] 37 78 [2] 70 7a [2] 37 6b [2] 79 67 [2] 75 6d [2] 62 66 [2] 79 28 [2] 44 }

  condition:
    any of them
}