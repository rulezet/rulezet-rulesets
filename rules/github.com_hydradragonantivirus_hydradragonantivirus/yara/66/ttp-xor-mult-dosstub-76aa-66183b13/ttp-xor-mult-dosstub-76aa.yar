rule TTP_XOR_MULT_DOSStub_76aa {
  strings:
    $key_76aa = { 22 c2 [2] 56 da [2] 11 d8 [2] 56 c9 [2] 18 c5 [2] 14 cf [2] 03 c4 [2] 18 8a [2] 25 }

  condition:
    any of them
}