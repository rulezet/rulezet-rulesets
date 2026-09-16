rule TTP_XOR_MULT_DOSStub_1faa {
  strings:
    $key_1faa = { 4b c2 [2] 3f da [2] 78 d8 [2] 3f c9 [2] 71 c5 [2] 7d cf [2] 6a c4 [2] 71 8a [2] 4c }

  condition:
    any of them
}