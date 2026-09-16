rule TTP_XOR_MULT_DOSStub_7102 {
  strings:
    $key_7102 = { 25 6a [2] 51 72 [2] 16 70 [2] 51 61 [2] 1f 6d [2] 13 67 [2] 04 6c [2] 1f 22 [2] 22 }

  condition:
    any of them
}