rule TTP_XOR_MULT_DOSStub_d6fc {
  strings:
    $key_d6fc = { 82 94 [2] f6 8c [2] b1 8e [2] f6 9f [2] b8 93 [2] b4 99 [2] a3 92 [2] b8 dc [2] 85 }

  condition:
    any of them
}