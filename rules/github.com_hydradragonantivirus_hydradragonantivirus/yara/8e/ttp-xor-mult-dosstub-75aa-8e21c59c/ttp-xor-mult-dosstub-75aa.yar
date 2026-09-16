rule TTP_XOR_MULT_DOSStub_75aa {
  strings:
    $key_75aa = { 21 c2 [2] 55 da [2] 12 d8 [2] 55 c9 [2] 1b c5 [2] 17 cf [2] 00 c4 [2] 1b 8a [2] 26 }

  condition:
    any of them
}