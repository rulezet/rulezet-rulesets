rule TTP_XOR_MULT_DOSStub_b7cb {
  strings:
    $key_b7cb = { e3 a3 [2] 97 bb [2] d0 b9 [2] 97 a8 [2] d9 a4 [2] d5 ae [2] c2 a5 [2] d9 eb [2] e4 }

  condition:
    any of them
}