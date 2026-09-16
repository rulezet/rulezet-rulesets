rule TTP_XOR_MULT_DOSStub_67e5 {
  strings:
    $key_67e5 = { 33 8d [2] 47 95 [2] 00 97 [2] 47 86 [2] 09 8a [2] 05 80 [2] 12 8b [2] 09 c5 [2] 34 }

  condition:
    any of them
}