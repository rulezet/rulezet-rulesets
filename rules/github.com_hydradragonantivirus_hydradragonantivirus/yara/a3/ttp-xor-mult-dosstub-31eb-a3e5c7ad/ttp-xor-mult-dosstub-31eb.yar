rule TTP_XOR_MULT_DOSStub_31eb {
  strings:
    $key_31eb = { 65 83 [2] 11 9b [2] 56 99 [2] 11 88 [2] 5f 84 [2] 53 8e [2] 44 85 [2] 5f cb [2] 62 }

  condition:
    any of them
}