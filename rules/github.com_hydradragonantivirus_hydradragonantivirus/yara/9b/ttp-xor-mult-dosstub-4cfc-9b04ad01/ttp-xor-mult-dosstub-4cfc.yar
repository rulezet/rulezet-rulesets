rule TTP_XOR_MULT_DOSStub_4cfc {
  strings:
    $key_4cfc = { 18 94 [2] 6c 8c [2] 2b 8e [2] 6c 9f [2] 22 93 [2] 2e 99 [2] 39 92 [2] 22 dc [2] 1f }

  condition:
    any of them
}