rule TTP_XOR_MULT_DOSStub_4626 {
  strings:
    $key_4626 = { 12 4e [2] 66 56 [2] 21 54 [2] 66 45 [2] 28 49 [2] 24 43 [2] 33 48 [2] 28 06 [2] 15 }

  condition:
    any of them
}