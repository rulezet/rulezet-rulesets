rule TTP_XOR_MULT_DOSStub_1a2d {
  strings:
    $key_1a2d = { 4e 45 [2] 3a 5d [2] 7d 5f [2] 3a 4e [2] 74 42 [2] 78 48 [2] 6f 43 [2] 74 0d [2] 49 }

  condition:
    any of them
}