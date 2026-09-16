rule TTP_XOR_MULT_DOSStub_187d {
  strings:
    $key_187d = { 4c 15 [2] 38 0d [2] 7f 0f [2] 38 1e [2] 76 12 [2] 7a 18 [2] 6d 13 [2] 76 5d [2] 4b }

  condition:
    any of them
}