rule TTP_XOR_MULT_DOSStub_bca8 {
  strings:
    $key_bca8 = { e8 c0 [2] 9c d8 [2] db da [2] 9c cb [2] d2 c7 [2] de cd [2] c9 c6 [2] d2 88 [2] ef }

  condition:
    any of them
}