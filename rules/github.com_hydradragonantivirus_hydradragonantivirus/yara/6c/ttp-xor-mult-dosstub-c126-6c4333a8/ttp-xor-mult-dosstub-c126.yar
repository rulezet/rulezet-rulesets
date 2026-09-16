rule TTP_XOR_MULT_DOSStub_c126 {
  strings:
    $key_c126 = { 95 4e [2] e1 56 [2] a6 54 [2] e1 45 [2] af 49 [2] a3 43 [2] b4 48 [2] af 06 [2] 92 }

  condition:
    any of them
}