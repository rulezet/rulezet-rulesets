rule TTP_XOR_MULT_DOSStub_54eb {
  strings:
    $key_54eb = { 00 83 [2] 74 9b [2] 33 99 [2] 74 88 [2] 3a 84 [2] 36 8e [2] 21 85 [2] 3a cb [2] 07 }

  condition:
    any of them
}