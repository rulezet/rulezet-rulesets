rule TTP_XOR_MULT_DOSStub_c674 {
  strings:
    $key_c674 = { 92 1c [2] e6 04 [2] a1 06 [2] e6 17 [2] a8 1b [2] a4 11 [2] b3 1a [2] a8 54 [2] 95 }

  condition:
    any of them
}