rule TTP_XOR_MULT_DOSStub_2dfc {
  strings:
    $key_2dfc = { 79 94 [2] 0d 8c [2] 4a 8e [2] 0d 9f [2] 43 93 [2] 4f 99 [2] 58 92 [2] 43 dc [2] 7e }

  condition:
    any of them
}