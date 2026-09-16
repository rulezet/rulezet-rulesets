rule TTP_XOR_MULT_DOSStub_31e6 {
  strings:
    $key_31e6 = { 65 8e [2] 11 96 [2] 56 94 [2] 11 85 [2] 5f 89 [2] 53 83 [2] 44 88 [2] 5f c6 [2] 62 }

  condition:
    any of them
}