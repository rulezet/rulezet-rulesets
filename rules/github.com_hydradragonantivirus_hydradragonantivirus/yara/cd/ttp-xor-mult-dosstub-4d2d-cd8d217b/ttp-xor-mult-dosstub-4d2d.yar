rule TTP_XOR_MULT_DOSStub_4d2d {
  strings:
    $key_4d2d = { 19 45 [2] 6d 5d [2] 2a 5f [2] 6d 4e [2] 23 42 [2] 2f 48 [2] 38 43 [2] 23 0d [2] 1e }

  condition:
    any of them
}