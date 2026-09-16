rule TTP_XOR_MULT_DOSStub_7cfa {
  strings:
    $key_7cfa = { 28 92 [2] 5c 8a [2] 1b 88 [2] 5c 99 [2] 12 95 [2] 1e 9f [2] 09 94 [2] 12 da [2] 2f }

  condition:
    any of them
}