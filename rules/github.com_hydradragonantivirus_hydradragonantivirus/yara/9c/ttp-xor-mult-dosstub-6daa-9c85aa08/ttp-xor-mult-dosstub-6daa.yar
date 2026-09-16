rule TTP_XOR_MULT_DOSStub_6daa {
  strings:
    $key_6daa = { 39 c2 [2] 4d da [2] 0a d8 [2] 4d c9 [2] 03 c5 [2] 0f cf [2] 18 c4 [2] 03 8a [2] 3e }

  condition:
    any of them
}