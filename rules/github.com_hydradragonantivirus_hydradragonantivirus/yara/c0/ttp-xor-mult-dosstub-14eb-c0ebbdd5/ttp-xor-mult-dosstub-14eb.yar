rule TTP_XOR_MULT_DOSStub_14eb {
  strings:
    $key_14eb = { 40 83 [2] 34 9b [2] 73 99 [2] 34 88 [2] 7a 84 [2] 76 8e [2] 61 85 [2] 7a cb [2] 47 }

  condition:
    any of them
}