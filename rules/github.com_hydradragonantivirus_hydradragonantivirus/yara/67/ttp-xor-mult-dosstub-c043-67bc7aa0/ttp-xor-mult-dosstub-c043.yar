rule TTP_XOR_MULT_DOSStub_c043 {
  strings:
    $key_c043 = { 94 2b [2] e0 33 [2] a7 31 [2] e0 20 [2] ae 2c [2] a2 26 [2] b5 2d [2] ae 63 [2] 93 }

  condition:
    any of them
}