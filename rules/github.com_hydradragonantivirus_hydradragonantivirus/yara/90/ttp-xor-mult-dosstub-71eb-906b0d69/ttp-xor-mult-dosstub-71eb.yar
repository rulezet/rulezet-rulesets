rule TTP_XOR_MULT_DOSStub_71eb {
  strings:
    $key_71eb = { 25 83 [2] 51 9b [2] 16 99 [2] 51 88 [2] 1f 84 [2] 13 8e [2] 04 85 [2] 1f cb [2] 22 }

  condition:
    any of them
}