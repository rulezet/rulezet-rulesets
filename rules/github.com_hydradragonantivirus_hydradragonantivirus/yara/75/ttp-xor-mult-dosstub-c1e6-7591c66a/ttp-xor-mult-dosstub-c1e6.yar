rule TTP_XOR_MULT_DOSStub_c1e6 {
  strings:
    $key_c1e6 = { 95 8e [2] e1 96 [2] a6 94 [2] e1 85 [2] af 89 [2] a3 83 [2] b4 88 [2] af c6 [2] 92 }

  condition:
    any of them
}