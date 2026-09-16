rule TTP_XOR_MULT_DOSStub_aadd {
  strings:
    $key_aadd = { fe b5 [2] 8a ad [2] cd af [2] 8a be [2] c4 b2 [2] c8 b8 [2] df b3 [2] c4 fd [2] f9 }

  condition:
    any of them
}