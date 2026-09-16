rule TTP_XOR_MULT_DOSStub_e3aa {
  strings:
    $key_e3aa = { b7 c2 [2] c3 da [2] 84 d8 [2] c3 c9 [2] 8d c5 [2] 81 cf [2] 96 c4 [2] 8d 8a [2] b0 }

  condition:
    any of them
}