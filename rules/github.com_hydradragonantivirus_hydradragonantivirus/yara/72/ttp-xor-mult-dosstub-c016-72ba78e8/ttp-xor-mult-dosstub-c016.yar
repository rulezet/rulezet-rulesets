rule TTP_XOR_MULT_DOSStub_c016 {
  strings:
    $key_c016 = { 94 7e [2] e0 66 [2] a7 64 [2] e0 75 [2] ae 79 [2] a2 73 [2] b5 78 [2] ae 36 [2] 93 }

  condition:
    any of them
}