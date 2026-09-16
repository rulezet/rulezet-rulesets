rule TTP_XOR_MULT_DOSStub_c146 {
  strings:
    $key_c146 = { 95 2e [2] e1 36 [2] a6 34 [2] e1 25 [2] af 29 [2] a3 23 [2] b4 28 [2] af 66 [2] 92 }

  condition:
    any of them
}