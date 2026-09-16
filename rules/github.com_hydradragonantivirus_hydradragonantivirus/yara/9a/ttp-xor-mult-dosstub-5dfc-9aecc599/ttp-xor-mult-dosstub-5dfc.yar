rule TTP_XOR_MULT_DOSStub_5dfc {
  strings:
    $key_5dfc = { 09 94 [2] 7d 8c [2] 3a 8e [2] 7d 9f [2] 33 93 [2] 3f 99 [2] 28 92 [2] 33 dc [2] 0e }

  condition:
    any of them
}