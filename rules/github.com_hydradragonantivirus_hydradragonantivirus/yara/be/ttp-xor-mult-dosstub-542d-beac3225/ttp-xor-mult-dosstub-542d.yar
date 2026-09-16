rule TTP_XOR_MULT_DOSStub_542d {
  strings:
    $key_542d = { 00 45 [2] 74 5d [2] 33 5f [2] 74 4e [2] 3a 42 [2] 36 48 [2] 21 43 [2] 3a 0d [2] 07 }

  condition:
    any of them
}