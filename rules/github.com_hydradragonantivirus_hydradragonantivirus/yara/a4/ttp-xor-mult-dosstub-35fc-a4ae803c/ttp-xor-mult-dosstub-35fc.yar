rule TTP_XOR_MULT_DOSStub_35fc {
  strings:
    $key_35fc = { 61 94 [2] 15 8c [2] 52 8e [2] 15 9f [2] 5b 93 [2] 57 99 [2] 40 92 [2] 5b dc [2] 66 }

  condition:
    any of them
}