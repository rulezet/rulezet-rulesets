rule TTP_XOR_MULT_DOSStub_5daa {
  strings:
    $key_5daa = { 09 c2 [2] 7d da [2] 3a d8 [2] 7d c9 [2] 33 c5 [2] 3f cf [2] 28 c4 [2] 33 8a [2] 0e }

  condition:
    any of them
}