rule TTP_XOR_MULT_DOSStub_c7ea {
  strings:
    $key_c7ea = { 93 82 [2] e7 9a [2] a0 98 [2] e7 89 [2] a9 85 [2] a5 8f [2] b2 84 [2] a9 ca [2] 94 }

  condition:
    any of them
}