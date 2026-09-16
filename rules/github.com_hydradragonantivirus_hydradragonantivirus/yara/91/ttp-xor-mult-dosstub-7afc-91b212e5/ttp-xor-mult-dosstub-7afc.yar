rule TTP_XOR_MULT_DOSStub_7afc {
  strings:
    $key_7afc = { 2e 94 [2] 5a 8c [2] 1d 8e [2] 5a 9f [2] 14 93 [2] 18 99 [2] 0f 92 [2] 14 dc [2] 29 }

  condition:
    any of them
}