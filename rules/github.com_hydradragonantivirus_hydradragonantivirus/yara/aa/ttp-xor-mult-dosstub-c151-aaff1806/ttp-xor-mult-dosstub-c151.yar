rule TTP_XOR_MULT_DOSStub_c151 {
  strings:
    $key_c151 = { 95 39 [2] e1 21 [2] a6 23 [2] e1 32 [2] af 3e [2] a3 34 [2] b4 3f [2] af 71 [2] 92 }

  condition:
    any of them
}