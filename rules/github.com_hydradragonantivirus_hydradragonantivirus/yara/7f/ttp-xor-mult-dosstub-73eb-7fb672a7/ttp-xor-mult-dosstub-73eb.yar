rule TTP_XOR_MULT_DOSStub_73eb {
  strings:
    $key_73eb = { 27 83 [2] 53 9b [2] 14 99 [2] 53 88 [2] 1d 84 [2] 11 8e [2] 06 85 [2] 1d cb [2] 20 }

  condition:
    any of them
}