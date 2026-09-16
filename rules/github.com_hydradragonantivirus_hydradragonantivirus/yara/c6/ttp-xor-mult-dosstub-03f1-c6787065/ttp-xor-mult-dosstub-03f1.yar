rule TTP_XOR_MULT_DOSStub_03f1 {
  strings:
    $key_03f1 = { 57 99 [2] 23 81 [2] 64 83 [2] 23 92 [2] 6d 9e [2] 61 94 [2] 76 9f [2] 6d d1 [2] 50 }

  condition:
    any of them
}