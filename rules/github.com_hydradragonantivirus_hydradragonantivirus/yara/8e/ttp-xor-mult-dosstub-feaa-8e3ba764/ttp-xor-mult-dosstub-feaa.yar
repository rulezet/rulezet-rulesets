rule TTP_XOR_MULT_DOSStub_feaa {
  strings:
    $key_feaa = { aa c2 [2] de da [2] 99 d8 [2] de c9 [2] 90 c5 [2] 9c cf [2] 8b c4 [2] 90 8a [2] ad }

  condition:
    any of them
}