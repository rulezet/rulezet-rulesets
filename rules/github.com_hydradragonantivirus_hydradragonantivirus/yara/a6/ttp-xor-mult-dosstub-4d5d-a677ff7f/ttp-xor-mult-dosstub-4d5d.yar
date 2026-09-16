rule TTP_XOR_MULT_DOSStub_4d5d {
  strings:
    $key_4d5d = { 19 35 [2] 6d 2d [2] 2a 2f [2] 6d 3e [2] 23 32 [2] 2f 38 [2] 38 33 [2] 23 7d [2] 1e }

  condition:
    any of them
}