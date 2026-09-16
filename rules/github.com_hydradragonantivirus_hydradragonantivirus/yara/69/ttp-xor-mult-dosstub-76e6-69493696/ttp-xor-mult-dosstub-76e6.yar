rule TTP_XOR_MULT_DOSStub_76e6 {
  strings:
    $key_76e6 = { 22 8e [2] 56 96 [2] 11 94 [2] 56 85 [2] 18 89 [2] 14 83 [2] 03 88 [2] 18 c6 [2] 25 }

  condition:
    any of them
}