rule TTP_XOR_MULT_DOSStub_fab7 {
  strings:
    $key_fab7 = { ae df [2] da c7 [2] 9d c5 [2] da d4 [2] 94 d8 [2] 98 d2 [2] 8f d9 [2] 94 97 [2] a9 }

  condition:
    any of them
}