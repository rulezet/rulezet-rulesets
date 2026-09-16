rule TTP_XOR_MULT_DOSStub_c108 {
  strings:
    $key_c108 = { 95 60 [2] e1 78 [2] a6 7a [2] e1 6b [2] af 67 [2] a3 6d [2] b4 66 [2] af 28 [2] 92 }

  condition:
    any of them
}