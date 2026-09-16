rule TTP_XOR_MULT_DOSStub_01eb {
  strings:
    $key_01eb = { 55 83 [2] 21 9b [2] 66 99 [2] 21 88 [2] 6f 84 [2] 63 8e [2] 74 85 [2] 6f cb [2] 52 }

  condition:
    any of them
}