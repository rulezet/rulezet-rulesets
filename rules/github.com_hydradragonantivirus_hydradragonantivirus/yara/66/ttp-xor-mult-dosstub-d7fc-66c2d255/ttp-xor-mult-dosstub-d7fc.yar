rule TTP_XOR_MULT_DOSStub_d7fc {
  strings:
    $key_d7fc = { 83 94 [2] f7 8c [2] b0 8e [2] f7 9f [2] b9 93 [2] b5 99 [2] a2 92 [2] b9 dc [2] 84 }

  condition:
    any of them
}