rule TTP_XOR_MULT_DOSStub_42aa {
  strings:
    $key_42aa = { 16 c2 [2] 62 da [2] 25 d8 [2] 62 c9 [2] 2c c5 [2] 20 cf [2] 37 c4 [2] 2c 8a [2] 11 }

  condition:
    any of them
}