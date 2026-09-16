rule TTP_XOR_MULT_DOSStub_5bfc {
  strings:
    $key_5bfc = { 0f 94 [2] 7b 8c [2] 3c 8e [2] 7b 9f [2] 35 93 [2] 39 99 [2] 2e 92 [2] 35 dc [2] 08 }

  condition:
    any of them
}