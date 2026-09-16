rule TTP_XOR_MULT_DOSStub_e744 {
  strings:
    $key_e744 = { b3 2c [2] c7 34 [2] 80 36 [2] c7 27 [2] 89 2b [2] 85 21 [2] 92 2a [2] 89 64 [2] b4 }

  condition:
    any of them
}