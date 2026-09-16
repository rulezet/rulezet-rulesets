rule TTP_XOR_MULT_DOSStub_6cfa {
  strings:
    $key_6cfa = { 38 92 [2] 4c 8a [2] 0b 88 [2] 4c 99 [2] 02 95 [2] 0e 9f [2] 19 94 [2] 02 da [2] 3f }

  condition:
    any of them
}