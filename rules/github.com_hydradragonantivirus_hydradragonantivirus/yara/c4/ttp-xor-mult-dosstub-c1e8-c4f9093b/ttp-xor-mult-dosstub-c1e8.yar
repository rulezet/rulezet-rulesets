rule TTP_XOR_MULT_DOSStub_c1e8 {
  strings:
    $key_c1e8 = { 95 80 [2] e1 98 [2] a6 9a [2] e1 8b [2] af 87 [2] a3 8d [2] b4 86 [2] af c8 [2] 92 }

  condition:
    any of them
}