rule TTP_XOR_MULT_DOSStub_67e7 {
  strings:
    $key_67e7 = { 33 8f [2] 47 97 [2] 00 95 [2] 47 84 [2] 09 88 [2] 05 82 [2] 12 89 [2] 09 c7 [2] 34 }

  condition:
    any of them
}