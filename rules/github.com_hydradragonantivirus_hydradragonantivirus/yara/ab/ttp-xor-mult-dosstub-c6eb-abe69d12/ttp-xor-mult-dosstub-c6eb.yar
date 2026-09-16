rule TTP_XOR_MULT_DOSStub_c6eb {
  strings:
    $key_c6eb = { 92 83 [2] e6 9b [2] a1 99 [2] e6 88 [2] a8 84 [2] a4 8e [2] b3 85 [2] a8 cb [2] 95 }

  condition:
    any of them
}