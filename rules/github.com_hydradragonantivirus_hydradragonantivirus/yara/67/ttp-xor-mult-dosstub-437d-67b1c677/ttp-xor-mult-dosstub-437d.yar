rule TTP_XOR_MULT_DOSStub_437d {
  strings:
    $key_437d = { 17 15 [2] 63 0d [2] 24 0f [2] 63 1e [2] 2d 12 [2] 21 18 [2] 36 13 [2] 2d 5d [2] 10 }

  condition:
    any of them
}