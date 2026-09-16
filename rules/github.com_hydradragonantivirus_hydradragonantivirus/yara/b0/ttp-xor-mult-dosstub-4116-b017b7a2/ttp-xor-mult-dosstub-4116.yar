rule TTP_XOR_MULT_DOSStub_4116 {
  strings:
    $key_4116 = { 15 7e [2] 61 66 [2] 26 64 [2] 61 75 [2] 2f 79 [2] 23 73 [2] 34 78 [2] 2f 36 [2] 12 }

  condition:
    any of them
}