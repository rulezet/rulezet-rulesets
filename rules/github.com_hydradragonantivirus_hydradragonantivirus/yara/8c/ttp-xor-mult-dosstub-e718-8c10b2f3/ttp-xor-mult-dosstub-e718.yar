rule TTP_XOR_MULT_DOSStub_e718 {
  strings:
    $key_e718 = { b3 70 [2] c7 68 [2] 80 6a [2] c7 7b [2] 89 77 [2] 85 7d [2] 92 76 [2] 89 38 [2] b4 }

  condition:
    any of them
}