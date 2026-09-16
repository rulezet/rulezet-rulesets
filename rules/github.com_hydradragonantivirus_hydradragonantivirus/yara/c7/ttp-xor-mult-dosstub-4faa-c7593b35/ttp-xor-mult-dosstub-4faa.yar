rule TTP_XOR_MULT_DOSStub_4faa {
  strings:
    $key_4faa = { 1b c2 [2] 6f da [2] 28 d8 [2] 6f c9 [2] 21 c5 [2] 2d cf [2] 3a c4 [2] 21 8a [2] 1c }

  condition:
    any of them
}