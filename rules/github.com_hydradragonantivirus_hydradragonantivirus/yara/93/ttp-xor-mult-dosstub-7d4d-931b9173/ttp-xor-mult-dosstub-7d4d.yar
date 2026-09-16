rule TTP_XOR_MULT_DOSStub_7d4d {
  strings:
    $key_7d4d = { 29 25 [2] 5d 3d [2] 1a 3f [2] 5d 2e [2] 13 22 [2] 1f 28 [2] 08 23 [2] 13 6d [2] 2e }

  condition:
    any of them
}