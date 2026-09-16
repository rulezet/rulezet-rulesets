rule TTP_XOR_MULT_DOSStub_73aa {
  strings:
    $key_73aa = { 27 c2 [2] 53 da [2] 14 d8 [2] 53 c9 [2] 1d c5 [2] 11 cf [2] 06 c4 [2] 1d 8a [2] 20 }

  condition:
    any of them
}