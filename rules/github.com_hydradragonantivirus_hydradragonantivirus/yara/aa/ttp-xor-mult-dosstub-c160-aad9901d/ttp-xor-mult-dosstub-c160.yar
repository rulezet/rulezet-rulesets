rule TTP_XOR_MULT_DOSStub_c160 {
  strings:
    $key_c160 = { 95 08 [2] e1 10 [2] a6 12 [2] e1 03 [2] af 0f [2] a3 05 [2] b4 0e [2] af 40 [2] 92 }

  condition:
    any of them
}