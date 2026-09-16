rule TTP_XOR_MULT_DOSStub_57aa {
  strings:
    $key_57aa = { 03 c2 [2] 77 da [2] 30 d8 [2] 77 c9 [2] 39 c5 [2] 35 cf [2] 22 c4 [2] 39 8a [2] 04 }

  condition:
    any of them
}