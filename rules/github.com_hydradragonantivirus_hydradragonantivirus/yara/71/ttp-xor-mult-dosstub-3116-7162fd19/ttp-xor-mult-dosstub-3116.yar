rule TTP_XOR_MULT_DOSStub_3116 {
  strings:
    $key_3116 = { 65 7e [2] 11 66 [2] 56 64 [2] 11 75 [2] 5f 79 [2] 53 73 [2] 44 78 [2] 5f 36 [2] 62 }

  condition:
    any of them
}