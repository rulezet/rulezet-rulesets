rule TTP_XOR_MULT_DOSStub_e738 {
  strings:
    $key_e738 = { b3 50 [2] c7 48 [2] 80 4a [2] c7 5b [2] 89 57 [2] 85 5d [2] 92 56 [2] 89 18 [2] b4 }

  condition:
    any of them
}