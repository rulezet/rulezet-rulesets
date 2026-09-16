rule TTP_XOR_MULT_DOSStub_4db9 {
  strings:
    $key_4db9 = { 19 d1 [2] 6d c9 [2] 2a cb [2] 6d da [2] 23 d6 [2] 2f dc [2] 38 d7 [2] 23 99 [2] 1e }

  condition:
    any of them
}