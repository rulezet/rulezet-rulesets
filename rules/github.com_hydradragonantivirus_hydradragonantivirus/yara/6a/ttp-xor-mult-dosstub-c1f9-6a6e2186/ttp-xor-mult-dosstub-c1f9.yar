rule TTP_XOR_MULT_DOSStub_c1f9 {
  strings:
    $key_c1f9 = { 95 91 [2] e1 89 [2] a6 8b [2] e1 9a [2] af 96 [2] a3 9c [2] b4 97 [2] af d9 [2] 92 }

  condition:
    any of them
}