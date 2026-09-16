rule TTP_XOR_MULT_DOSStub_74e5 {
  strings:
    $key_74e5 = { 20 8d [2] 54 95 [2] 13 97 [2] 54 86 [2] 1a 8a [2] 16 80 [2] 01 8b [2] 1a c5 [2] 27 }

  condition:
    any of them
}