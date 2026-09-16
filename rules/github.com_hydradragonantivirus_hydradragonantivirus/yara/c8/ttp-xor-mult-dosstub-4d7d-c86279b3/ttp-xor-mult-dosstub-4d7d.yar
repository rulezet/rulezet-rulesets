rule TTP_XOR_MULT_DOSStub_4d7d {
  strings:
    $key_4d7d = { 19 15 [2] 6d 0d [2] 2a 0f [2] 6d 1e [2] 23 12 [2] 2f 18 [2] 38 13 [2] 23 5d [2] 1e }

  condition:
    any of them
}