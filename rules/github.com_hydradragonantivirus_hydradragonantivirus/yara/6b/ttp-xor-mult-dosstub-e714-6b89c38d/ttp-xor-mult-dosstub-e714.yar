rule TTP_XOR_MULT_DOSStub_e714 {
  strings:
    $key_e714 = { b3 7c [2] c7 64 [2] 80 66 [2] c7 77 [2] 89 7b [2] 85 71 [2] 92 7a [2] 89 34 [2] b4 }

  condition:
    any of them
}