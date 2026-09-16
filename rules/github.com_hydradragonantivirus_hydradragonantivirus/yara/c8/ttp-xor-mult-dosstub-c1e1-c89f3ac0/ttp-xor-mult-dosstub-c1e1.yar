rule TTP_XOR_MULT_DOSStub_c1e1 {
  strings:
    $key_c1e1 = { 95 89 [2] e1 91 [2] a6 93 [2] e1 82 [2] af 8e [2] a3 84 [2] b4 8f [2] af c1 [2] 92 }

  condition:
    any of them
}