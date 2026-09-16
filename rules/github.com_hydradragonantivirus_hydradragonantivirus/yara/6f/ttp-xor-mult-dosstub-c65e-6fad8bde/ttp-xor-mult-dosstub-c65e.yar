rule TTP_XOR_MULT_DOSStub_c65e {
  strings:
    $key_c65e = { 92 36 [2] e6 2e [2] a1 2c [2] e6 3d [2] a8 31 [2] a4 3b [2] b3 30 [2] a8 7e [2] 95 }

  condition:
    any of them
}