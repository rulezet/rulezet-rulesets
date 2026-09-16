rule TTP_XOR_MULT_DOSStub_c743 {
  strings:
    $key_c743 = { 93 2b [2] e7 33 [2] a0 31 [2] e7 20 [2] a9 2c [2] a5 26 [2] b2 2d [2] a9 63 [2] 94 }

  condition:
    any of them
}