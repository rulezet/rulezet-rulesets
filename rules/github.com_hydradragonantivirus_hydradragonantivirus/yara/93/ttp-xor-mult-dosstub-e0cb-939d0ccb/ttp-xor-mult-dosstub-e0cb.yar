rule TTP_XOR_MULT_DOSStub_e0cb {
  strings:
    $key_e0cb = { b4 a3 [2] c0 bb [2] 87 b9 [2] c0 a8 [2] 8e a4 [2] 82 ae [2] 95 a5 [2] 8e eb [2] b3 }

  condition:
    any of them
}