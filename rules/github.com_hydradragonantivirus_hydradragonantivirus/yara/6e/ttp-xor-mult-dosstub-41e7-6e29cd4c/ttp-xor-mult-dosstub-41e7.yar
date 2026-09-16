rule TTP_XOR_MULT_DOSStub_41e7 {
  strings:
    $key_41e7 = { 15 8f [2] 61 97 [2] 26 95 [2] 61 84 [2] 2f 88 [2] 23 82 [2] 34 89 [2] 2f c7 [2] 12 }

  condition:
    any of them
}