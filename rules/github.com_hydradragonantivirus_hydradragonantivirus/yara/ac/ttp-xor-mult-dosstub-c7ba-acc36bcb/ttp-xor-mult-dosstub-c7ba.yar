rule TTP_XOR_MULT_DOSStub_c7ba {
  strings:
    $key_c7ba = { 93 d2 [2] e7 ca [2] a0 c8 [2] e7 d9 [2] a9 d5 [2] a5 df [2] b2 d4 [2] a9 9a [2] 94 }

  condition:
    any of them
}