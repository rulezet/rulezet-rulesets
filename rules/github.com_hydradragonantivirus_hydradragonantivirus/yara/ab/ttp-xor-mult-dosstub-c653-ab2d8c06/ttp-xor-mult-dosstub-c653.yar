rule TTP_XOR_MULT_DOSStub_c653 {
  strings:
    $key_c653 = { 92 3b [2] e6 23 [2] a1 21 [2] e6 30 [2] a8 3c [2] a4 36 [2] b3 3d [2] a8 73 [2] 95 }

  condition:
    any of them
}