rule TTP_XOR_MULT_DOSStub_15aa {
  strings:
    $key_15aa = { 41 c2 [2] 35 da [2] 72 d8 [2] 35 c9 [2] 7b c5 [2] 77 cf [2] 60 c4 [2] 7b 8a [2] 46 }

  condition:
    any of them
}