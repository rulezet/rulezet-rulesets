rule TTP_XOR_MULT_DOSStub_1ffc {
  strings:
    $key_1ffc = { 4b 94 [2] 3f 8c [2] 78 8e [2] 3f 9f [2] 71 93 [2] 7d 99 [2] 6a 92 [2] 71 dc [2] 4c }

  condition:
    any of them
}