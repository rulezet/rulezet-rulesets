rule TTP_XOR_MULT_DOSStub_c624 {
  strings:
    $key_c624 = { 92 4c [2] e6 54 [2] a1 56 [2] e6 47 [2] a8 4b [2] a4 41 [2] b3 4a [2] a8 04 [2] 95 }

  condition:
    any of them
}