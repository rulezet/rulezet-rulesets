rule TTP_XOR_MULT_DOSStub_39aa {
  strings:
    $key_39aa = { 6d c2 [2] 19 da [2] 5e d8 [2] 19 c9 [2] 57 c5 [2] 5b cf [2] 4c c4 [2] 57 8a [2] 6a }

  condition:
    any of them
}