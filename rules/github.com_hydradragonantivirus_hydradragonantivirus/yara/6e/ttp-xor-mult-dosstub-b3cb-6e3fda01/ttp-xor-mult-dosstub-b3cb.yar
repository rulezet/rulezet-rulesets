rule TTP_XOR_MULT_DOSStub_b3cb {
  strings:
    $key_b3cb = { e7 a3 [2] 93 bb [2] d4 b9 [2] 93 a8 [2] dd a4 [2] d1 ae [2] c6 a5 [2] dd eb [2] e0 }

  condition:
    any of them
}