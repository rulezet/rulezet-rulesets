rule TTP_XOR_MULT_DOSStub_e733 {
  strings:
    $key_e733 = { b3 5b [2] c7 43 [2] 80 41 [2] c7 50 [2] 89 5c [2] 85 56 [2] 92 5d [2] 89 13 [2] b4 }

  condition:
    any of them
}