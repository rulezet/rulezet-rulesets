rule TTP_XOR_MULT_DOSStub_bb98 {
  strings:
    $key_bb98 = { ef f0 [2] 9b e8 [2] dc ea [2] 9b fb [2] d5 f7 [2] d9 fd [2] ce f6 [2] d5 b8 [2] e8 }

  condition:
    any of them
}