rule TTP_XOR_MULT_DOSStub_2ffc {
  strings:
    $key_2ffc = { 7b 94 [2] 0f 8c [2] 48 8e [2] 0f 9f [2] 41 93 [2] 4d 99 [2] 5a 92 [2] 41 dc [2] 7c }

  condition:
    any of them
}