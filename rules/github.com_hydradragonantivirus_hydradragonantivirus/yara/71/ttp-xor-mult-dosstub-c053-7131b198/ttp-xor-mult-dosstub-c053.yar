rule TTP_XOR_MULT_DOSStub_c053 {
  strings:
    $key_c053 = { 94 3b [2] e0 23 [2] a7 21 [2] e0 30 [2] ae 3c [2] a2 36 [2] b5 3d [2] ae 73 [2] 93 }

  condition:
    any of them
}