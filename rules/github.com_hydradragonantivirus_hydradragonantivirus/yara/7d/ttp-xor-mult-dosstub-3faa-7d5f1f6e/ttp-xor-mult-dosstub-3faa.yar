rule TTP_XOR_MULT_DOSStub_3faa {
  strings:
    $key_3faa = { 6b c2 [2] 1f da [2] 58 d8 [2] 1f c9 [2] 51 c5 [2] 5d cf [2] 4a c4 [2] 51 8a [2] 6c }

  condition:
    any of them
}