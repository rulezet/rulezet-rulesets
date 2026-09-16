rule TTP_XOR_MULT_DOSStub_6db9 {
  strings:
    $key_6db9 = { 39 d1 [2] 4d c9 [2] 0a cb [2] 4d da [2] 03 d6 [2] 0f dc [2] 18 d7 [2] 03 99 [2] 3e }

  condition:
    any of them
}