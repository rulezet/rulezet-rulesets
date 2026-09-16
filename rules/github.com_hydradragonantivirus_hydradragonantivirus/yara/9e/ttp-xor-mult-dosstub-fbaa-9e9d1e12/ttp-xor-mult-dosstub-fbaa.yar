rule TTP_XOR_MULT_DOSStub_fbaa {
  strings:
    $key_fbaa = { af c2 [2] db da [2] 9c d8 [2] db c9 [2] 95 c5 [2] 99 cf [2] 8e c4 [2] 95 8a [2] a8 }

  condition:
    any of them
}