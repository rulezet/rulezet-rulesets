rule TTP_XOR_MULT_DOSStub_45eb {
  strings:
    $key_45eb = { 11 83 [2] 65 9b [2] 22 99 [2] 65 88 [2] 2b 84 [2] 27 8e [2] 30 85 [2] 2b cb [2] 16 }

  condition:
    any of them
}