rule TTP_XOR_MULT_DOSStub_beaa {
  strings:
    $key_beaa = { ea c2 [2] 9e da [2] d9 d8 [2] 9e c9 [2] d0 c5 [2] dc cf [2] cb c4 [2] d0 8a [2] ed }

  condition:
    any of them
}