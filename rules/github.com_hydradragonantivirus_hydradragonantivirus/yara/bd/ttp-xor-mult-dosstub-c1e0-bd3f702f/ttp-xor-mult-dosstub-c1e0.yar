rule TTP_XOR_MULT_DOSStub_c1e0 {
  strings:
    $key_c1e0 = { 95 88 [2] e1 90 [2] a6 92 [2] e1 83 [2] af 8f [2] a3 85 [2] b4 8e [2] af c0 [2] 92 }

  condition:
    any of them
}