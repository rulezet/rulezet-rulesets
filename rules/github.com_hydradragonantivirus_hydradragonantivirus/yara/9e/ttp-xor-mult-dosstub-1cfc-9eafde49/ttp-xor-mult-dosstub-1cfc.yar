rule TTP_XOR_MULT_DOSStub_1cfc {
  strings:
    $key_1cfc = { 48 94 [2] 3c 8c [2] 7b 8e [2] 3c 9f [2] 72 93 [2] 7e 99 [2] 69 92 [2] 72 dc [2] 4f }

  condition:
    any of them
}