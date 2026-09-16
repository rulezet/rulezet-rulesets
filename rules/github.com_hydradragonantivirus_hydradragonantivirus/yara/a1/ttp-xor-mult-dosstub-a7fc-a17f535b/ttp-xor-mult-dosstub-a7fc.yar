rule TTP_XOR_MULT_DOSStub_a7fc {
  strings:
    $key_a7fc = { f3 94 [2] 87 8c [2] c0 8e [2] 87 9f [2] c9 93 [2] c5 99 [2] d2 92 [2] c9 dc [2] f4 }

  condition:
    any of them
}