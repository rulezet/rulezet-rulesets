rule TTP_XOR_MULT_DOSStub_c516 {
  strings:
    $key_c516 = { 91 7e [2] e5 66 [2] a2 64 [2] e5 75 [2] ab 79 [2] a7 73 [2] b0 78 [2] ab 36 [2] 96 }

  condition:
    any of them
}