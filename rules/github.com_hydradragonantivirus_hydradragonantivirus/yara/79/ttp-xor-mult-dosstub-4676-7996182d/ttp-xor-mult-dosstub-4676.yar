rule TTP_XOR_MULT_DOSStub_4676 {
  strings:
    $key_4676 = { 12 1e [2] 66 06 [2] 21 04 [2] 66 15 [2] 28 19 [2] 24 13 [2] 33 18 [2] 28 56 [2] 15 }

  condition:
    any of them
}