rule TTP_XOR_MULT_DOSStub_44e6 {
  strings:
    $key_44e6 = { 10 8e [2] 64 96 [2] 23 94 [2] 64 85 [2] 2a 89 [2] 26 83 [2] 31 88 [2] 2a c6 [2] 17 }

  condition:
    any of them
}