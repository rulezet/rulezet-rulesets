rule TTP_XOR_MULT_DOSStub_52aa {
  strings:
    $key_52aa = { 06 c2 [2] 72 da [2] 35 d8 [2] 72 c9 [2] 3c c5 [2] 30 cf [2] 27 c4 [2] 3c 8a [2] 01 }

  condition:
    any of them
}