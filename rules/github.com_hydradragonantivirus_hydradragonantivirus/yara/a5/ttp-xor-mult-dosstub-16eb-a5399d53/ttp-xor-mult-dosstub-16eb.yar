rule TTP_XOR_MULT_DOSStub_16eb {
  strings:
    $key_16eb = { 42 83 [2] 36 9b [2] 71 99 [2] 36 88 [2] 78 84 [2] 74 8e [2] 63 85 [2] 78 cb [2] 45 }

  condition:
    any of them
}