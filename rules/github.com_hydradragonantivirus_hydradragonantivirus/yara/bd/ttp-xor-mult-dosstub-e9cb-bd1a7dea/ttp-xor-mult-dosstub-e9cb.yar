rule TTP_XOR_MULT_DOSStub_e9cb {
  strings:
    $key_e9cb = { bd a3 [2] c9 bb [2] 8e b9 [2] c9 a8 [2] 87 a4 [2] 8b ae [2] 9c a5 [2] 87 eb [2] ba }

  condition:
    any of them
}