rule TTP_XOR_MULT_DOSStub_c723 {
  strings:
    $key_c723 = { 93 4b [2] e7 53 [2] a0 51 [2] e7 40 [2] a9 4c [2] a5 46 [2] b2 4d [2] a9 03 [2] 94 }

  condition:
    any of them
}