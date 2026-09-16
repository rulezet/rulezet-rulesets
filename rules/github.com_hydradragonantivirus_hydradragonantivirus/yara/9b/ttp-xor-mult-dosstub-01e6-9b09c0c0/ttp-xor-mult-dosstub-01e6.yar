rule TTP_XOR_MULT_DOSStub_01e6 {
  strings:
    $key_01e6 = { 55 8e [2] 21 96 [2] 66 94 [2] 21 85 [2] 6f 89 [2] 63 83 [2] 74 88 [2] 6f c6 [2] 52 }

  condition:
    any of them
}