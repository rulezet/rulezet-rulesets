rule TTP_XOR_MULT_DOSStub_c64e {
  strings:
    $key_c64e = { 92 26 [2] e6 3e [2] a1 3c [2] e6 2d [2] a8 21 [2] a4 2b [2] b3 20 [2] a8 6e [2] 95 }

  condition:
    any of them
}