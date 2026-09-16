rule TTP_XOR_MULT_DOSStub_e039 {
  strings:
    $key_e039 = { b4 51 [2] c0 49 [2] 87 4b [2] c0 5a [2] 8e 56 [2] 82 5c [2] 95 57 [2] 8e 19 [2] b3 }

  condition:
    any of them
}