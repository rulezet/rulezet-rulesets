rule TTP_XOR_MULT_DOSStub_c4ae {
  strings:
    $key_c4ae = { 90 c6 [2] e4 de [2] a3 dc [2] e4 cd [2] aa c1 [2] a6 cb [2] b1 c0 [2] aa 8e [2] 97 }

  condition:
    any of them
}