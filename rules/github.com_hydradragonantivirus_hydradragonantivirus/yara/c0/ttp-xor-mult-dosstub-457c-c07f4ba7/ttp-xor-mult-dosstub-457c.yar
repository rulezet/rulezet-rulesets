rule TTP_XOR_MULT_DOSStub_457c {
  strings:
    $key_457c = { 11 14 [2] 65 0c [2] 22 0e [2] 65 1f [2] 2b 13 [2] 27 19 [2] 30 12 [2] 2b 5c [2] 16 }

  condition:
    any of them
}