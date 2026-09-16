rule TTP_XOR_MULT_DOSStub_39cb {
  strings:
    $key_39cb = { 6d a3 [2] 19 bb [2] 5e b9 [2] 19 a8 [2] 57 a4 [2] 5b ae [2] 4c a5 [2] 57 eb [2] 6a }

  condition:
    any of them
}