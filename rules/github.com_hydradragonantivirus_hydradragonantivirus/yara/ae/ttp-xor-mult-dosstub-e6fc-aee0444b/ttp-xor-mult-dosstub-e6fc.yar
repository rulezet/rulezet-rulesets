rule TTP_XOR_MULT_DOSStub_e6fc {
  strings:
    $key_e6fc = { b2 94 [2] c6 8c [2] 81 8e [2] c6 9f [2] 88 93 [2] 84 99 [2] 93 92 [2] 88 dc [2] b5 }

  condition:
    any of them
}