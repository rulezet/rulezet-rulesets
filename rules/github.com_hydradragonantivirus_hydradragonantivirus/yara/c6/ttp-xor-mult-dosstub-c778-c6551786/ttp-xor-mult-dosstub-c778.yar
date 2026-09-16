rule TTP_XOR_MULT_DOSStub_c778 {
  strings:
    $key_c778 = { 93 10 [2] e7 08 [2] a0 0a [2] e7 1b [2] a9 17 [2] a5 1d [2] b2 16 [2] a9 58 [2] 94 }

  condition:
    any of them
}