rule TTP_XOR_MULT_DOSStub_e2f5 {
  strings:
    $key_e2f5 = { b6 9d [2] c2 85 [2] 85 87 [2] c2 96 [2] 8c 9a [2] 80 90 [2] 97 9b [2] 8c d5 [2] b1 }

  condition:
    any of them
}