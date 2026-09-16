rule TTP_XOR_MULT_DOSStub_c120 {
  strings:
    $key_c120 = { 95 48 [2] e1 50 [2] a6 52 [2] e1 43 [2] af 4f [2] a3 45 [2] b4 4e [2] af 00 [2] 92 }

  condition:
    any of them
}