rule TTP_XOR_MULT_DOSStub_7116 {
  strings:
    $key_7116 = { 25 7e [2] 51 66 [2] 16 64 [2] 51 75 [2] 1f 79 [2] 13 73 [2] 04 78 [2] 1f 36 [2] 22 }

  condition:
    any of them
}