rule TTP_XOR_MULT_DOSStub_c728 {
  strings:
    $key_c728 = { 93 40 [2] e7 58 [2] a0 5a [2] e7 4b [2] a9 47 [2] a5 4d [2] b2 46 [2] a9 08 [2] 94 }

  condition:
    any of them
}