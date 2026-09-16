rule TTP_XOR_MULT_DOSStub_c6cb {
  strings:
    $key_c6cb = { 92 a3 [2] e6 bb [2] a1 b9 [2] e6 a8 [2] a8 a4 [2] a4 ae [2] b3 a5 [2] a8 eb [2] 95 }

  condition:
    any of them
}