rule TTP_XOR_MULT_DOSStub_44e7 {
  strings:
    $key_44e7 = { 10 8f [2] 64 97 [2] 23 95 [2] 64 84 [2] 2a 88 [2] 26 82 [2] 31 89 [2] 2a c7 [2] 17 }

  condition:
    any of them
}