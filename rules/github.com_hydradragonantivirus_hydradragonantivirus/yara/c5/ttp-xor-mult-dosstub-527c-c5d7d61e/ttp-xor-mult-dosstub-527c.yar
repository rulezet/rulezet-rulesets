rule TTP_XOR_MULT_DOSStub_527c {
  strings:
    $key_527c = { 06 14 [2] 72 0c [2] 35 0e [2] 72 1f [2] 3c 13 [2] 30 19 [2] 27 12 [2] 3c 5c [2] 01 }

  condition:
    any of them
}