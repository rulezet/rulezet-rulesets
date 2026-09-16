rule TTP_XOR_MULT_DOSStub_08eb {
  strings:
    $key_08eb = { 5c 83 [2] 28 9b [2] 6f 99 [2] 28 88 [2] 66 84 [2] 6a 8e [2] 7d 85 [2] 66 cb [2] 5b }

  condition:
    any of them
}