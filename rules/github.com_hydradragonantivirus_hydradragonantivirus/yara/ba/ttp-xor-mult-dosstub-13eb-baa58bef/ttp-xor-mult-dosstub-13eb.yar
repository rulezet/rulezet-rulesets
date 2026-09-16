rule TTP_XOR_MULT_DOSStub_13eb {
  strings:
    $key_13eb = { 47 83 [2] 33 9b [2] 74 99 [2] 33 88 [2] 7d 84 [2] 71 8e [2] 66 85 [2] 7d cb [2] 40 }

  condition:
    any of them
}