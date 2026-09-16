rule TTP_XOR_MULT_DOSStub_e7cb {
  strings:
    $key_e7cb = { b3 a3 [2] c7 bb [2] 80 b9 [2] c7 a8 [2] 89 a4 [2] 85 ae [2] 92 a5 [2] 89 eb [2] b4 }

  condition:
    any of them
}