rule TTP_XOR_MULT_DOSStub_c67c {
  strings:
    $key_c67c = { 92 14 [2] e6 0c [2] a1 0e [2] e6 1f [2] a8 13 [2] a4 19 [2] b3 12 [2] a8 5c [2] 95 }

  condition:
    any of them
}