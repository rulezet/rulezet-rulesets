rule TTP_XOR_MULT_DOSStub_03fc {
  strings:
    $key_03fc = { 57 94 [2] 23 8c [2] 64 8e [2] 23 9f [2] 6d 93 [2] 61 99 [2] 76 92 [2] 6d dc [2] 50 }

  condition:
    any of them
}