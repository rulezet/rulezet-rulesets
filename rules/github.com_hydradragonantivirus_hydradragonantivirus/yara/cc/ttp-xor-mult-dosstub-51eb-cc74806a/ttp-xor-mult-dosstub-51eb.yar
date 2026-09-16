rule TTP_XOR_MULT_DOSStub_51eb {
  strings:
    $key_51eb = { 05 83 [2] 71 9b [2] 36 99 [2] 71 88 [2] 3f 84 [2] 33 8e [2] 24 85 [2] 3f cb [2] 02 }

  condition:
    any of them
}