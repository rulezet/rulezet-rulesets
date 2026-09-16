rule TTP_XOR_MULT_DOSStub_3daa {
  strings:
    $key_3daa = { 69 c2 [2] 1d da [2] 5a d8 [2] 1d c9 [2] 53 c5 [2] 5f cf [2] 48 c4 [2] 53 8a [2] 6e }

  condition:
    any of them
}