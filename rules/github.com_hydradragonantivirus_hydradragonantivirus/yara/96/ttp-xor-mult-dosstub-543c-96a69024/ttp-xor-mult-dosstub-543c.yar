rule TTP_XOR_MULT_DOSStub_543c {
  strings:
    $key_543c = { 00 54 [2] 74 4c [2] 33 4e [2] 74 5f [2] 3a 53 [2] 36 59 [2] 21 52 [2] 3a 1c [2] 07 }

  condition:
    any of them
}