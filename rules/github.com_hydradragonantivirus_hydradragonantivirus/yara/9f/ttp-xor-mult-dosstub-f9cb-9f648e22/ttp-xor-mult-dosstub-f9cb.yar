rule TTP_XOR_MULT_DOSStub_f9cb {
  strings:
    $key_f9cb = { ad a3 [2] d9 bb [2] 9e b9 [2] d9 a8 [2] 97 a4 [2] 9b ae [2] 8c a5 [2] 97 eb [2] aa }

  condition:
    any of them
}