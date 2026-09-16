rule TTP_XOR_MULT_DOSStub_17fc {
  strings:
    $key_17fc = { 43 94 [2] 37 8c [2] 70 8e [2] 37 9f [2] 79 93 [2] 75 99 [2] 62 92 [2] 79 dc [2] 44 }

  condition:
    any of them
}