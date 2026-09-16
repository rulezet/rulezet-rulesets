rule TTP_XOR_MULT_DOSStub_03eb {
  strings:
    $key_03eb = { 57 83 [2] 23 9b [2] 64 99 [2] 23 88 [2] 6d 84 [2] 61 8e [2] 76 85 [2] 6d cb [2] 50 }

  condition:
    any of them
}