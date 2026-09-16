rule TTP_XOR_MULT_DOSStub_23eb {
  strings:
    $key_23eb = { 77 83 [2] 03 9b [2] 44 99 [2] 03 88 [2] 4d 84 [2] 41 8e [2] 56 85 [2] 4d cb [2] 70 }

  condition:
    any of them
}