rule TTP_XOR_MULT_DOSStub_d8fc {
  strings:
    $key_d8fc = { 8c 94 [2] f8 8c [2] bf 8e [2] f8 9f [2] b6 93 [2] ba 99 [2] ad 92 [2] b6 dc [2] 8b }

  condition:
    any of them
}