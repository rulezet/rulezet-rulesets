rule TTP_XOR_MULT_DOSStub_4a7c {
  strings:
    $key_4a7c = { 1e 14 [2] 6a 0c [2] 2d 0e [2] 6a 1f [2] 24 13 [2] 28 19 [2] 3f 12 [2] 24 5c [2] 19 }

  condition:
    any of them
}