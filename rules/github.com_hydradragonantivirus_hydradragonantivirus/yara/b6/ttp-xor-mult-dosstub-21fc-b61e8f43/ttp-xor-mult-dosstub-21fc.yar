rule TTP_XOR_MULT_DOSStub_21fc {
  strings:
    $key_21fc = { 75 94 [2] 01 8c [2] 46 8e [2] 01 9f [2] 4f 93 [2] 43 99 [2] 54 92 [2] 4f dc [2] 72 }

  condition:
    any of them
}