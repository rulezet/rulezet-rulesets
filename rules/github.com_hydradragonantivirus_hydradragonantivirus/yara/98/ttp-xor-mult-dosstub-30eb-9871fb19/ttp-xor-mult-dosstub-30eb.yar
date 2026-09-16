rule TTP_XOR_MULT_DOSStub_30eb {
  strings:
    $key_30eb = { 64 83 [2] 10 9b [2] 57 99 [2] 10 88 [2] 5e 84 [2] 52 8e [2] 45 85 [2] 5e cb [2] 63 }

  condition:
    any of them
}