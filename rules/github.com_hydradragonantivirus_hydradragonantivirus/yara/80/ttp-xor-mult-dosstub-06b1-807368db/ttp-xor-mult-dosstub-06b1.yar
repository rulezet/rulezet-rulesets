rule TTP_XOR_MULT_DOSStub_06b1 {
  strings:
    $key_06b1 = { 52 d9 [2] 26 c1 [2] 61 c3 [2] 26 d2 [2] 68 de [2] 64 d4 [2] 73 df [2] 68 91 [2] 55 }

  condition:
    any of them
}