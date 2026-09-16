rule TTP_XOR_MULT_DOSStub_41e6 {
  strings:
    $key_41e6 = { 15 8e [2] 61 96 [2] 26 94 [2] 61 85 [2] 2f 89 [2] 23 83 [2] 34 88 [2] 2f c6 [2] 12 }

  condition:
    any of them
}