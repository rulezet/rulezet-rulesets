rule TTP_XOR_MULT_DOSStub_87fc {
  strings:
    $key_87fc = { d3 94 [2] a7 8c [2] e0 8e [2] a7 9f [2] e9 93 [2] e5 99 [2] f2 92 [2] e9 dc [2] d4 }

  condition:
    any of them
}