rule TTP_XOR_MULT_DOSStub_397c {
  strings:
    $key_397c = { 6d 14 [2] 19 0c [2] 5e 0e [2] 19 1f [2] 57 13 [2] 5b 19 [2] 4c 12 [2] 57 5c [2] 6a }

  condition:
    any of them
}