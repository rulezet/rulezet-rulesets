rule TTP_XOR_MULT_DOSStub_20e5 {
  strings:
    $key_20e5 = { 74 8d [2] 00 95 [2] 47 97 [2] 00 86 [2] 4e 8a [2] 42 80 [2] 55 8b [2] 4e c5 [2] 73 }

  condition:
    any of them
}