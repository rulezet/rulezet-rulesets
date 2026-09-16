rule TTP_XOR_MULT_DOSStub_44aa {
  strings:
    $key_44aa = { 10 c2 [2] 64 da [2] 23 d8 [2] 64 c9 [2] 2a c5 [2] 26 cf [2] 31 c4 [2] 2a 8a [2] 17 }

  condition:
    any of them
}