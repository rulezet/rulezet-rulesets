rule TTP_XOR_MULT_DOSStub_b2cb {
  strings:
    $key_b2cb = { e6 a3 [2] 92 bb [2] d5 b9 [2] 92 a8 [2] dc a4 [2] d0 ae [2] c7 a5 [2] dc eb [2] e1 }

  condition:
    any of them
}