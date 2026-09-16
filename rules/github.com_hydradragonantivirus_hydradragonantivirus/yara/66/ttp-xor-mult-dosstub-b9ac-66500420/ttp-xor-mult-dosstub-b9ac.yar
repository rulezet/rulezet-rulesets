rule TTP_XOR_MULT_DOSStub_b9ac {
  strings:
    $key_b9ac = { ed c4 [2] 99 dc [2] de de [2] 99 cf [2] d7 c3 [2] db c9 [2] cc c2 [2] d7 8c [2] ea }

  condition:
    any of them
}