rule TTP_XOR_MULT_DOSStub_2a7c {
  strings:
    $key_2a7c = { 7e 14 [2] 0a 0c [2] 4d 0e [2] 0a 1f [2] 44 13 [2] 48 19 [2] 5f 12 [2] 44 5c [2] 79 }

  condition:
    any of them
}