rule TTP_XOR_MULT_DOSStub_7bfc {
  strings:
    $key_7bfc = { 2f 94 [2] 5b 8c [2] 1c 8e [2] 5b 9f [2] 15 93 [2] 19 99 [2] 0e 92 [2] 15 dc [2] 28 }

  condition:
    any of them
}