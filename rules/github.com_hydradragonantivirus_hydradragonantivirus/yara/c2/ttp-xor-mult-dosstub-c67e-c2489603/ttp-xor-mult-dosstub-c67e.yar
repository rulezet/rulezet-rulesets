rule TTP_XOR_MULT_DOSStub_c67e {
  strings:
    $key_c67e = { 92 16 [2] e6 0e [2] a1 0c [2] e6 1d [2] a8 11 [2] a4 1b [2] b3 10 [2] a8 5e [2] 95 }

  condition:
    any of them
}