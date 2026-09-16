rule TTP_XOR_MULT_DOSStub_20f2 {
  strings:
    $key_20f2 = { 74 9a [2] 00 82 [2] 47 80 [2] 00 91 [2] 4e 9d [2] 42 97 [2] 55 9c [2] 4e d2 [2] 73 }

  condition:
    any of them
}