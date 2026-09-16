rule TTP_XOR_MULT_DOSStub_e7e4 {
  strings:
    $key_e7e4 = { b3 8c [2] c7 94 [2] 80 96 [2] c7 87 [2] 89 8b [2] 85 81 [2] 92 8a [2] 89 c4 [2] b4 }

  condition:
    any of them
}