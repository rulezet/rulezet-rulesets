rule TTP_XOR_MULT_DOSStub_c601 {
  strings:
    $key_c601 = { 92 69 [2] e6 71 [2] a1 73 [2] e6 62 [2] a8 6e [2] a4 64 [2] b3 6f [2] a8 21 [2] 95 }

  condition:
    any of them
}