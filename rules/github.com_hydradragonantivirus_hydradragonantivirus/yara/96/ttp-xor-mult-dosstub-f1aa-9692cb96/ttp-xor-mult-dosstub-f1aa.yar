rule TTP_XOR_MULT_DOSStub_f1aa {
  strings:
    $key_f1aa = { a5 c2 [2] d1 da [2] 96 d8 [2] d1 c9 [2] 9f c5 [2] 93 cf [2] 84 c4 [2] 9f 8a [2] a2 }

  condition:
    any of them
}