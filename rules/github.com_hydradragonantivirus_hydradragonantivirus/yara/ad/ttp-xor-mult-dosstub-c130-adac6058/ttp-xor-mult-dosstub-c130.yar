rule TTP_XOR_MULT_DOSStub_c130 {
  strings:
    $key_c130 = { 95 58 [2] e1 40 [2] a6 42 [2] e1 53 [2] af 5f [2] a3 55 [2] b4 5e [2] af 10 [2] 92 }

  condition:
    any of them
}