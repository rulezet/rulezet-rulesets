rule TTP_XOR_MULT_DOSStub_e759 {
  strings:
    $key_e759 = { b3 31 [2] c7 29 [2] 80 2b [2] c7 3a [2] 89 36 [2] 85 3c [2] 92 37 [2] 89 79 [2] b4 }

  condition:
    any of them
}