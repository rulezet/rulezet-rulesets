rule TTP_XOR_MULT_DOSStub_c0ba {
  strings:
    $key_c0ba = { 94 d2 [2] e0 ca [2] a7 c8 [2] e0 d9 [2] ae d5 [2] a2 df [2] b5 d4 [2] ae 9a [2] 93 }

  condition:
    any of them
}