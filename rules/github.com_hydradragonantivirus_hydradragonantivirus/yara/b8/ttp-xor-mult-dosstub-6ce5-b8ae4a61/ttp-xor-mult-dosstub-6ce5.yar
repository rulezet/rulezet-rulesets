rule TTP_XOR_MULT_DOSStub_6ce5 {
  strings:
    $key_6ce5 = { 38 8d [2] 4c 95 [2] 0b 97 [2] 4c 86 [2] 02 8a [2] 0e 80 [2] 19 8b [2] 02 c5 [2] 3f }

  condition:
    any of them
}