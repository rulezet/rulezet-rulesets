rule TTP_XOR_MULT_DOSStub_c0a2 {
  strings:
    $key_c0a2 = { 94 ca [2] e0 d2 [2] a7 d0 [2] e0 c1 [2] ae cd [2] a2 c7 [2] b5 cc [2] ae 82 [2] 93 }

  condition:
    any of them
}