rule TTP_XOR_MULT_DOSStub_75fc {
  strings:
    $key_75fc = { 21 94 [2] 55 8c [2] 12 8e [2] 55 9f [2] 1b 93 [2] 17 99 [2] 00 92 [2] 1b dc [2] 26 }

  condition:
    any of them
}