rule TTP_XOR_MULT_DOSStub_0faa {
  strings:
    $key_0faa = { 5b c2 [2] 2f da [2] 68 d8 [2] 2f c9 [2] 61 c5 [2] 6d cf [2] 7a c4 [2] 61 8a [2] 5c }

  condition:
    any of them
}