rule TTP_XOR_MULT_DOSStub_39a9 {
  strings:
    $key_39a9 = { 6d c1 [2] 19 d9 [2] 5e db [2] 19 ca [2] 57 c6 [2] 5b cc [2] 4c c7 [2] 57 89 [2] 6a }

  condition:
    any of them
}