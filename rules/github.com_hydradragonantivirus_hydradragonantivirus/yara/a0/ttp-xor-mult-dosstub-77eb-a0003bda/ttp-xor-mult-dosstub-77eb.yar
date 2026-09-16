rule TTP_XOR_MULT_DOSStub_77eb {
  strings:
    $key_77eb = { 23 83 [2] 57 9b [2] 10 99 [2] 57 88 [2] 19 84 [2] 15 8e [2] 02 85 [2] 19 cb [2] 24 }

  condition:
    any of them
}