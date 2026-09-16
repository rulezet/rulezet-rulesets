rule TTP_XOR_MULT_DOSStub_e734 {
  strings:
    $key_e734 = { b3 5c [2] c7 44 [2] 80 46 [2] c7 57 [2] 89 5b [2] 85 51 [2] 92 5a [2] 89 14 [2] b4 }

  condition:
    any of them
}