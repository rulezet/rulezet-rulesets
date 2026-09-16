rule TTP_XOR_MULT_DOSStub_36eb {
  strings:
    $key_36eb = { 62 83 [2] 16 9b [2] 51 99 [2] 16 88 [2] 58 84 [2] 54 8e [2] 43 85 [2] 58 cb [2] 65 }

  condition:
    any of them
}