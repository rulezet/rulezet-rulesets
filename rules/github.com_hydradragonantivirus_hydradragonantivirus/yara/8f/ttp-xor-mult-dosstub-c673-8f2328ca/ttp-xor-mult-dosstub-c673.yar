rule TTP_XOR_MULT_DOSStub_c673 {
  strings:
    $key_c673 = { 92 1b [2] e6 03 [2] a1 01 [2] e6 10 [2] a8 1c [2] a4 16 [2] b3 1d [2] a8 53 [2] 95 }

  condition:
    any of them
}