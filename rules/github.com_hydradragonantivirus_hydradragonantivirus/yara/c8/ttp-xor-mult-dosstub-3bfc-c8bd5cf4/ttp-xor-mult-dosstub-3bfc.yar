rule TTP_XOR_MULT_DOSStub_3bfc {
  strings:
    $key_3bfc = { 6f 94 [2] 1b 8c [2] 5c 8e [2] 1b 9f [2] 55 93 [2] 59 99 [2] 4e 92 [2] 55 dc [2] 68 }

  condition:
    any of them
}