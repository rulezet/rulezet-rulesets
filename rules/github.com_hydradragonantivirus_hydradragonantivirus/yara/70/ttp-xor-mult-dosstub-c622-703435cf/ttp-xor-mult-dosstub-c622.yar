rule TTP_XOR_MULT_DOSStub_c622 {
  strings:
    $key_c622 = { 92 4a [2] e6 52 [2] a1 50 [2] e6 41 [2] a8 4d [2] a4 47 [2] b3 4c [2] a8 02 [2] 95 }

  condition:
    any of them
}