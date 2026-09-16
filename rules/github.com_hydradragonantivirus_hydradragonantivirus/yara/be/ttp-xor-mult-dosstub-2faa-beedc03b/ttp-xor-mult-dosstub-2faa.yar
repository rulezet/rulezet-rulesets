rule TTP_XOR_MULT_DOSStub_2faa {
  strings:
    $key_2faa = { 7b c2 [2] 0f da [2] 48 d8 [2] 0f c9 [2] 41 c5 [2] 4d cf [2] 5a c4 [2] 41 8a [2] 7c }

  condition:
    any of them
}