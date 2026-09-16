rule TTP_XOR_MULT_DOSStub_54e5 {
  strings:
    $key_54e5 = { 00 8d [2] 74 95 [2] 33 97 [2] 74 86 [2] 3a 8a [2] 36 80 [2] 21 8b [2] 3a c5 [2] 07 }

  condition:
    any of them
}