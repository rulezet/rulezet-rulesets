rule TTP_XOR_MULT_DOSStub_e014 {
  strings:
    $key_e014 = { b4 7c [2] c0 64 [2] 87 66 [2] c0 77 [2] 8e 7b [2] 82 71 [2] 95 7a [2] 8e 34 [2] b3 }

  condition:
    any of them
}