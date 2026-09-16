rule TTP_XOR_MULT_DOSStub_6ffc {
  strings:
    $key_6ffc = { 3b 94 [2] 4f 8c [2] 08 8e [2] 4f 9f [2] 01 93 [2] 0d 99 [2] 1a 92 [2] 01 dc [2] 3c }

  condition:
    any of them
}