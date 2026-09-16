rule TTP_XOR_MULT_DOSStub_c603 {
  strings:
    $key_c603 = { 92 6b [2] e6 73 [2] a1 71 [2] e6 60 [2] a8 6c [2] a4 66 [2] b3 6d [2] a8 23 [2] 95 }

  condition:
    any of them
}