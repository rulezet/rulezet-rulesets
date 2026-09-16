rule TTP_XOR_MULT_DOSStub_763c {
  strings:
    $key_763c = { 22 54 [2] 56 4c [2] 11 4e [2] 56 5f [2] 18 53 [2] 14 59 [2] 03 52 [2] 18 1c [2] 25 }

  condition:
    any of them
}