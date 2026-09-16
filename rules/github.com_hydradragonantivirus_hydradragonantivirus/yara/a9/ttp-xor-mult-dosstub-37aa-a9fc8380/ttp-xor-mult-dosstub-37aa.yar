rule TTP_XOR_MULT_DOSStub_37aa {
  strings:
    $key_37aa = { 63 c2 [2] 17 da [2] 50 d8 [2] 17 c9 [2] 59 c5 [2] 55 cf [2] 42 c4 [2] 59 8a [2] 64 }

  condition:
    any of them
}