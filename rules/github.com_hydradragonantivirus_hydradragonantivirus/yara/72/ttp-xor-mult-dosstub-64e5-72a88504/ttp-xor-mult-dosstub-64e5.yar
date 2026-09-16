rule TTP_XOR_MULT_DOSStub_64e5 {
  strings:
    $key_64e5 = { 30 8d [2] 44 95 [2] 03 97 [2] 44 86 [2] 0a 8a [2] 06 80 [2] 11 8b [2] 0a c5 [2] 37 }

  condition:
    any of them
}