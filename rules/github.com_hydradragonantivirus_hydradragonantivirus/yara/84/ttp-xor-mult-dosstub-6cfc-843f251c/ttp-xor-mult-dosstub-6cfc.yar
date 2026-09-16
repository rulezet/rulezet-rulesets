rule TTP_XOR_MULT_DOSStub_6cfc {
  strings:
    $key_6cfc = { 38 94 [2] 4c 8c [2] 0b 8e [2] 4c 9f [2] 02 93 [2] 0e 99 [2] 19 92 [2] 02 dc [2] 3f }

  condition:
    any of them
}