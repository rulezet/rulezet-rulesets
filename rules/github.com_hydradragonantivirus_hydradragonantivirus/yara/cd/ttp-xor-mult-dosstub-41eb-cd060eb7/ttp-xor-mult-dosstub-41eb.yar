rule TTP_XOR_MULT_DOSStub_41eb {
  strings:
    $key_41eb = { 15 83 [2] 61 9b [2] 26 99 [2] 61 88 [2] 2f 84 [2] 23 8e [2] 34 85 [2] 2f cb [2] 12 }

  condition:
    any of them
}