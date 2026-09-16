rule TTP_XOR_MULT_DOSStub_c1f7 {
  strings:
    $key_c1f7 = { 95 9f [2] e1 87 [2] a6 85 [2] e1 94 [2] af 98 [2] a3 92 [2] b4 99 [2] af d7 [2] 92 }

  condition:
    any of them
}