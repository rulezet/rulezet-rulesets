rule TTP_XOR_MULT_DOSStub_2efc {
  strings:
    $key_2efc = { 7a 94 [2] 0e 8c [2] 49 8e [2] 0e 9f [2] 40 93 [2] 4c 99 [2] 5b 92 [2] 40 dc [2] 7d }

  condition:
    any of them
}