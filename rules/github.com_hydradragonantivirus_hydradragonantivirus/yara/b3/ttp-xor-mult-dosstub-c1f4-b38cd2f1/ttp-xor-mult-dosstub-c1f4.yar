rule TTP_XOR_MULT_DOSStub_c1f4 {
  strings:
    $key_c1f4 = { 95 9c [2] e1 84 [2] a6 86 [2] e1 97 [2] af 9b [2] a3 91 [2] b4 9a [2] af d4 [2] 92 }

  condition:
    any of them
}