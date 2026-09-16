rule TTP_XOR_MULT_DOSStub_e6cb {
  strings:
    $key_e6cb = { b2 a3 [2] c6 bb [2] 81 b9 [2] c6 a8 [2] 88 a4 [2] 84 ae [2] 93 a5 [2] 88 eb [2] b5 }

  condition:
    any of them
}