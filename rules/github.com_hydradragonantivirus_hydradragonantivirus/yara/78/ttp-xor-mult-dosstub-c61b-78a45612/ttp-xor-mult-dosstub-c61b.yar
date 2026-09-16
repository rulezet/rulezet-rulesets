rule TTP_XOR_MULT_DOSStub_c61b {
  strings:
    $key_c61b = { 92 73 [2] e6 6b [2] a1 69 [2] e6 78 [2] a8 74 [2] a4 7e [2] b3 75 [2] a8 3b [2] 95 }

  condition:
    any of them
}