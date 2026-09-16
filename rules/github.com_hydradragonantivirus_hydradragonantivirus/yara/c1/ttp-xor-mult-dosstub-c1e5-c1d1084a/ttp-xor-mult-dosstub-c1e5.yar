rule TTP_XOR_MULT_DOSStub_c1e5 {
  strings:
    $key_c1e5 = { 95 8d [2] e1 95 [2] a6 97 [2] e1 86 [2] af 8a [2] a3 80 [2] b4 8b [2] af c5 [2] 92 }

  condition:
    any of them
}