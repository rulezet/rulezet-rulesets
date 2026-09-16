rule TTP_XOR_MULT_DOSStub_31aa {
  strings:
    $key_31aa = { 65 c2 [2] 11 da [2] 56 d8 [2] 11 c9 [2] 5f c5 [2] 53 cf [2] 44 c4 [2] 5f 8a [2] 62 }

  condition:
    any of them
}