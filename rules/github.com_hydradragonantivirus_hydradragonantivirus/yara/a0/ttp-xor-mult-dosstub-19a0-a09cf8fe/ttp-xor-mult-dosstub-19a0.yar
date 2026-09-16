rule TTP_XOR_MULT_DOSStub_19a0 {
  strings:
    $key_19a0 = { 4d c8 [2] 39 d0 [2] 7e d2 [2] 39 c3 [2] 77 cf [2] 7b c5 [2] 6c ce [2] 77 80 [2] 4a }

  condition:
    any of them
}