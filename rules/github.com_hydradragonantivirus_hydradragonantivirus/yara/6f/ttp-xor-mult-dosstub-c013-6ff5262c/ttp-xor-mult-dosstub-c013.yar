rule TTP_XOR_MULT_DOSStub_c013 {
  strings:
    $key_c013 = { 94 7b [2] e0 63 [2] a7 61 [2] e0 70 [2] ae 7c [2] a2 76 [2] b5 7d [2] ae 33 [2] 93 }

  condition:
    any of them
}