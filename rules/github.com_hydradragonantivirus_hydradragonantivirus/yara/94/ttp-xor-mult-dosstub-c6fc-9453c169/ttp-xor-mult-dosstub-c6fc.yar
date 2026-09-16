rule TTP_XOR_MULT_DOSStub_c6fc {
  strings:
    $key_c6fc = { 92 94 [2] e6 8c [2] a1 8e [2] e6 9f [2] a8 93 [2] a4 99 [2] b3 92 [2] a8 dc [2] 95 }

  condition:
    any of them
}