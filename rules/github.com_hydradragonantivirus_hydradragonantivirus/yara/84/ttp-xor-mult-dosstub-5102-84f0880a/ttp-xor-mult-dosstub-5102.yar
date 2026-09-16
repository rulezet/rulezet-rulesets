rule TTP_XOR_MULT_DOSStub_5102 {
  strings:
    $key_5102 = { 05 6a [2] 71 72 [2] 36 70 [2] 71 61 [2] 3f 6d [2] 33 67 [2] 24 6c [2] 3f 22 [2] 02 }

  condition:
    any of them
}