rule TTP_XOR_MULT_DOSStub_75eb {
  strings:
    $key_75eb = { 21 83 [2] 55 9b [2] 12 99 [2] 55 88 [2] 1b 84 [2] 17 8e [2] 00 85 [2] 1b cb [2] 26 }

  condition:
    any of them
}