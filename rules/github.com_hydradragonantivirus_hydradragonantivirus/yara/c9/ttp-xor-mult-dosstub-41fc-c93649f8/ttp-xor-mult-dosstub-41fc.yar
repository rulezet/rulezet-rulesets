rule TTP_XOR_MULT_DOSStub_41fc {
  strings:
    $key_41fc = { 15 94 [2] 61 8c [2] 26 8e [2] 61 9f [2] 2f 93 [2] 23 99 [2] 34 92 [2] 2f dc [2] 12 }

  condition:
    any of them
}