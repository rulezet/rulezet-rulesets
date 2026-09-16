rule TTP_XOR_MULT_DOSStub_c069 {
  strings:
    $key_c069 = { 94 01 [2] e0 19 [2] a7 1b [2] e0 0a [2] ae 06 [2] a2 0c [2] b5 07 [2] ae 49 [2] 93 }

  condition:
    any of them
}