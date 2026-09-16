rule TTP_XOR_MULT_DOSStub_46e7 {
  strings:
    $key_46e7 = { 12 8f [2] 66 97 [2] 21 95 [2] 66 84 [2] 28 88 [2] 24 82 [2] 33 89 [2] 28 c7 [2] 15 }

  condition:
    any of them
}