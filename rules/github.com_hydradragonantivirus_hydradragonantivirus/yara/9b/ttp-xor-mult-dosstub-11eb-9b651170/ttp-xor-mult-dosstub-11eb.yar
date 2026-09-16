rule TTP_XOR_MULT_DOSStub_11eb {
  strings:
    $key_11eb = { 45 83 [2] 31 9b [2] 76 99 [2] 31 88 [2] 7f 84 [2] 73 8e [2] 64 85 [2] 7f cb [2] 42 }

  condition:
    any of them
}