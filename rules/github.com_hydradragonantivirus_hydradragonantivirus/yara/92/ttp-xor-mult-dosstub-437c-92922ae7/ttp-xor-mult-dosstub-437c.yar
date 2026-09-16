rule TTP_XOR_MULT_DOSStub_437c {
  strings:
    $key_437c = { 17 14 [2] 63 0c [2] 24 0e [2] 63 1f [2] 2d 13 [2] 21 19 [2] 36 12 [2] 2d 5c [2] 10 }

  condition:
    any of them
}