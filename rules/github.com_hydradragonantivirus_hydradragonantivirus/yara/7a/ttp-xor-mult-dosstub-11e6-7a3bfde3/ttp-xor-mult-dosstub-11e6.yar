rule TTP_XOR_MULT_DOSStub_11e6 {
  strings:
    $key_11e6 = { 45 8e [2] 31 96 [2] 76 94 [2] 31 85 [2] 7f 89 [2] 73 83 [2] 64 88 [2] 7f c6 [2] 42 }

  condition:
    any of them
}