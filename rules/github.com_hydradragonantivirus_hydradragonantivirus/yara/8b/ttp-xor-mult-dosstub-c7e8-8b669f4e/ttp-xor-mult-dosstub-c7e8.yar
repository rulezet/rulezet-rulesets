rule TTP_XOR_MULT_DOSStub_c7e8 {
  strings:
    $key_c7e8 = { 93 80 [2] e7 98 [2] a0 9a [2] e7 8b [2] a9 87 [2] a5 8d [2] b2 86 [2] a9 c8 [2] 94 }

  condition:
    any of them
}