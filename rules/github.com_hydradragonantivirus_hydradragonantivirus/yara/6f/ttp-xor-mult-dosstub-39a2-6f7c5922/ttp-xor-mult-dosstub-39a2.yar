rule TTP_XOR_MULT_DOSStub_39a2 {
  strings:
    $key_39a2 = { 6d ca [2] 19 d2 [2] 5e d0 [2] 19 c1 [2] 57 cd [2] 5b c7 [2] 4c cc [2] 57 82 [2] 6a }

  condition:
    any of them
}