rule TTP_XOR_MULT_DOSStub_c61e {
  strings:
    $key_c61e = { 92 76 [2] e6 6e [2] a1 6c [2] e6 7d [2] a8 71 [2] a4 7b [2] b3 70 [2] a8 3e [2] 95 }

  condition:
    any of them
}