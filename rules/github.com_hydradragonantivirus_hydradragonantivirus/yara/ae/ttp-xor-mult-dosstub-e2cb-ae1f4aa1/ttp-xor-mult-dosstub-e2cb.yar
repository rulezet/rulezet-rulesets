rule TTP_XOR_MULT_DOSStub_e2cb {
  strings:
    $key_e2cb = { b6 a3 [2] c2 bb [2] 85 b9 [2] c2 a8 [2] 8c a4 [2] 80 ae [2] 97 a5 [2] 8c eb [2] b1 }

  condition:
    any of them
}