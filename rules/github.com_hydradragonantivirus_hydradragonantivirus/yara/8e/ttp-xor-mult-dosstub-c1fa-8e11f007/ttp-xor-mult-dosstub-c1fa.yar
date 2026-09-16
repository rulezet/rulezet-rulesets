rule TTP_XOR_MULT_DOSStub_c1fa {
  strings:
    $key_c1fa = { 95 92 [2] e1 8a [2] a6 88 [2] e1 99 [2] af 95 [2] a3 9f [2] b4 94 [2] af da [2] 92 }

  condition:
    any of them
}