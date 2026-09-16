rule TTP_XOR_MULT_DOSStub_0ffc {
  strings:
    $key_0ffc = { 5b 94 [2] 2f 8c [2] 68 8e [2] 2f 9f [2] 61 93 [2] 6d 99 [2] 7a 92 [2] 61 dc [2] 5c }

  condition:
    any of them
}