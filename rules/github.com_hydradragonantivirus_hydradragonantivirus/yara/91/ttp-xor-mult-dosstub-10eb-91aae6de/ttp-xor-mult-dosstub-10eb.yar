rule TTP_XOR_MULT_DOSStub_10eb {
  strings:
    $key_10eb = { 44 83 [2] 30 9b [2] 77 99 [2] 30 88 [2] 7e 84 [2] 72 8e [2] 65 85 [2] 7e cb [2] 43 }

  condition:
    any of them
}