rule TTP_XOR_MULT_DOSStub_04aa {
  strings:
    $key_04aa = { 50 c2 [2] 24 da [2] 63 d8 [2] 24 c9 [2] 6a c5 [2] 66 cf [2] 71 c4 [2] 6a 8a [2] 57 }

  condition:
    any of them
}