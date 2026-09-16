rule TTP_XOR_MULT_DOSStub_e038 {
  strings:
    $key_e038 = { b4 50 [2] c0 48 [2] 87 4a [2] c0 5b [2] 8e 57 [2] 82 5d [2] 95 56 [2] 8e 18 [2] b3 }

  condition:
    any of them
}