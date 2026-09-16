rule TTP_XOR_MULT_DOSStub_177c {
  strings:
    $key_177c = { 43 14 [2] 37 0c [2] 70 0e [2] 37 1f [2] 79 13 [2] 75 19 [2] 62 12 [2] 79 5c [2] 44 }

  condition:
    any of them
}