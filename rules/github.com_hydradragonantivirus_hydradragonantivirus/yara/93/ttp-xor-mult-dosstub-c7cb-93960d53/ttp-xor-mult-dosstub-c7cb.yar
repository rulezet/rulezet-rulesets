rule TTP_XOR_MULT_DOSStub_c7cb {
  strings:
    $key_c7cb = { 93 a3 [2] e7 bb [2] a0 b9 [2] e7 a8 [2] a9 a4 [2] a5 ae [2] b2 a5 [2] a9 eb [2] 94 }

  condition:
    any of them
}