rule TTP_XOR_MULT_DOSStub_2a7d {
  strings:
    $key_2a7d = { 7e 15 [2] 0a 0d [2] 4d 0f [2] 0a 1e [2] 44 12 [2] 48 18 [2] 5f 13 [2] 44 5d [2] 79 }

  condition:
    any of them
}