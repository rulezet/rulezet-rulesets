rule TTP_XOR_MULT_DOSStub_5db9 {
  strings:
    $key_5db9 = { 09 d1 [2] 7d c9 [2] 3a cb [2] 7d da [2] 33 d6 [2] 3f dc [2] 28 d7 [2] 33 99 [2] 0e }

  condition:
    any of them
}