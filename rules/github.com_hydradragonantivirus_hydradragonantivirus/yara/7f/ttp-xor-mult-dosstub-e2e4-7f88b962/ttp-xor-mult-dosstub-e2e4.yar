rule TTP_XOR_MULT_DOSStub_e2e4 {
  strings:
    $key_e2e4 = { b6 8c [2] c2 94 [2] 85 96 [2] c2 87 [2] 8c 8b [2] 80 81 [2] 97 8a [2] 8c c4 [2] b1 }

  condition:
    any of them
}