rule TTP_XOR_MULT_DOSStub_baaa {
  strings:
    $key_baaa = { ee c2 [2] 9a da [2] dd d8 [2] 9a c9 [2] d4 c5 [2] d8 cf [2] cf c4 [2] d4 8a [2] e9 }

  condition:
    any of them
}