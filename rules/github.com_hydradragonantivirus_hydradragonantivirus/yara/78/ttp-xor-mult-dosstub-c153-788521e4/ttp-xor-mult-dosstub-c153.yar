rule TTP_XOR_MULT_DOSStub_c153 {
  strings:
    $key_c153 = { 95 3b [2] e1 23 [2] a6 21 [2] e1 30 [2] af 3c [2] a3 36 [2] b4 3d [2] af 73 [2] 92 }

  condition:
    any of them
}