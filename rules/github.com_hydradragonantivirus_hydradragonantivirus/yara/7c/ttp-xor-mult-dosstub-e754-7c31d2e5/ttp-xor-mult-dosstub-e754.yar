rule TTP_XOR_MULT_DOSStub_e754 {
  strings:
    $key_e754 = { b3 3c [2] c7 24 [2] 80 26 [2] c7 37 [2] 89 3b [2] 85 31 [2] 92 3a [2] 89 74 [2] b4 }

  condition:
    any of them
}