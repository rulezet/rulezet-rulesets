rule TTP_XOR_MULT_DOSStub_e019 {
  strings:
    $key_e019 = { b4 71 [2] c0 69 [2] 87 6b [2] c0 7a [2] 8e 76 [2] 82 7c [2] 95 77 [2] 8e 39 [2] b3 }

  condition:
    any of them
}