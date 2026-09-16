rule TTP_XOR_MULT_DOSStub_c4eb {
  strings:
    $key_c4eb = { 90 83 [2] e4 9b [2] a3 99 [2] e4 88 [2] aa 84 [2] a6 8e [2] b1 85 [2] aa cb [2] 97 }

  condition:
    any of them
}