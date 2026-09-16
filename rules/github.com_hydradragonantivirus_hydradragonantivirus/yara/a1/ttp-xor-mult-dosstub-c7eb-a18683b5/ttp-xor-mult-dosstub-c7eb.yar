rule TTP_XOR_MULT_DOSStub_c7eb {
  strings:
    $key_c7eb = { 93 83 [2] e7 9b [2] a0 99 [2] e7 88 [2] a9 84 [2] a5 8e [2] b2 85 [2] a9 cb [2] 94 }

  condition:
    any of them
}