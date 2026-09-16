rule TTP_XOR_MULT_DOSStub_c110 {
  strings:
    $key_c110 = { 95 78 [2] e1 60 [2] a6 62 [2] e1 73 [2] af 7f [2] a3 75 [2] b4 7e [2] af 30 [2] 92 }

  condition:
    any of them
}