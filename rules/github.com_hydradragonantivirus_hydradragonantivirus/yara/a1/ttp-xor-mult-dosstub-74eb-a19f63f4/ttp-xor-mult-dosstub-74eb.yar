rule TTP_XOR_MULT_DOSStub_74eb {
  strings:
    $key_74eb = { 20 83 [2] 54 9b [2] 13 99 [2] 54 88 [2] 1a 84 [2] 16 8e [2] 01 85 [2] 1a cb [2] 27 }

  condition:
    any of them
}