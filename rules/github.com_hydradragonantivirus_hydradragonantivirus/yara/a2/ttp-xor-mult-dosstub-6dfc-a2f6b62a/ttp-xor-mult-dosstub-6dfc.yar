rule TTP_XOR_MULT_DOSStub_6dfc {
  strings:
    $key_6dfc = { 39 94 [2] 4d 8c [2] 0a 8e [2] 4d 9f [2] 03 93 [2] 0f 99 [2] 18 92 [2] 03 dc [2] 3e }

  condition:
    any of them
}