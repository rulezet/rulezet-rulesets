rule TTP_XOR_MULT_DOSStub_e5c5 {
  strings:
    $key_e5c5 = { b1 ad [2] c5 b5 [2] 82 b7 [2] c5 a6 [2] 8b aa [2] 87 a0 [2] 90 ab [2] 8b e5 [2] b6 }

  condition:
    any of them
}