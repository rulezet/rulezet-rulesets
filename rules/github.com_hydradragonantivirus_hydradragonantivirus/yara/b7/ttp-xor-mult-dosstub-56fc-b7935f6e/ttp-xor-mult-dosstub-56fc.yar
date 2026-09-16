rule TTP_XOR_MULT_DOSStub_56fc {
  strings:
    $key_56fc = { 02 94 [2] 76 8c [2] 31 8e [2] 76 9f [2] 38 93 [2] 34 99 [2] 23 92 [2] 38 dc [2] 05 }

  condition:
    any of them
}