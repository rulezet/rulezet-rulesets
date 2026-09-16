rule TTP_XOR_MULT_DOSStub_68eb {
  strings:
    $key_68eb = { 3c 83 [2] 48 9b [2] 0f 99 [2] 48 88 [2] 06 84 [2] 0a 8e [2] 1d 85 [2] 06 cb [2] 3b }

  condition:
    any of them
}