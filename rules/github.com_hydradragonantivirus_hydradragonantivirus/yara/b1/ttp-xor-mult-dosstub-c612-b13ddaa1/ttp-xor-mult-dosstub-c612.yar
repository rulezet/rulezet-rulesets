rule TTP_XOR_MULT_DOSStub_c612 {
  strings:
    $key_c612 = { 92 7a [2] e6 62 [2] a1 60 [2] e6 71 [2] a8 7d [2] a4 77 [2] b3 7c [2] a8 32 [2] 95 }

  condition:
    any of them
}