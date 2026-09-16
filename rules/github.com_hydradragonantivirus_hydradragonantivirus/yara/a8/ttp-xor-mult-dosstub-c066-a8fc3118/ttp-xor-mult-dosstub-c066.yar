rule TTP_XOR_MULT_DOSStub_c066 {
  strings:
    $key_c066 = { 94 0e [2] e0 16 [2] a7 14 [2] e0 05 [2] ae 09 [2] a2 03 [2] b5 08 [2] ae 46 [2] 93 }

  condition:
    any of them
}