rule TTP_XOR_MULT_DOSStub_c0eb {
  strings:
    $key_c0eb = { 94 83 [2] e0 9b [2] a7 99 [2] e0 88 [2] ae 84 [2] a2 8e [2] b5 85 [2] ae cb [2] 93 }

  condition:
    any of them
}