rule TTP_XOR_MULT_DOSStub_e005 {
  strings:
    $key_e005 = { b4 6d [2] c0 75 [2] 87 77 [2] c0 66 [2] 8e 6a [2] 82 60 [2] 95 6b [2] 8e 25 [2] b3 }

  condition:
    any of them
}