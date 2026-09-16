rule TTP_XOR_MULT_DOSStub_1bfc {
  strings:
    $key_1bfc = { 4f 94 [2] 3b 8c [2] 7c 8e [2] 3b 9f [2] 75 93 [2] 79 99 [2] 6e 92 [2] 75 dc [2] 48 }

  condition:
    any of them
}