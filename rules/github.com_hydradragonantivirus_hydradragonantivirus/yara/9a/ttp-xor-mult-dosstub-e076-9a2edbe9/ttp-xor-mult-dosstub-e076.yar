rule TTP_XOR_MULT_DOSStub_e076 {
  strings:
    $key_e076 = { b4 1e [2] c0 06 [2] 87 04 [2] c0 15 [2] 8e 19 [2] 82 13 [2] 95 18 [2] 8e 56 [2] b3 }

  condition:
    any of them
}