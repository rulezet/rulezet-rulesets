rule TTP_XOR_MULT_DOSStub_2bfc {
  strings:
    $key_2bfc = { 7f 94 [2] 0b 8c [2] 4c 8e [2] 0b 9f [2] 45 93 [2] 49 99 [2] 5e 92 [2] 45 dc [2] 78 }

  condition:
    any of them
}