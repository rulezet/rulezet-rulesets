rule TTP_XOR_MULT_DOSStub_3ffc {
  strings:
    $key_3ffc = { 6b 94 [2] 1f 8c [2] 58 8e [2] 1f 9f [2] 51 93 [2] 5d 99 [2] 4a 92 [2] 51 dc [2] 6c }

  condition:
    any of them
}