rule TTP_XOR_MULT_DOSStub_03f6 {
  strings:
    $key_03f6 = { 57 9e [2] 23 86 [2] 64 84 [2] 23 95 [2] 6d 99 [2] 61 93 [2] 76 98 [2] 6d d6 [2] 50 }

  condition:
    any of them
}