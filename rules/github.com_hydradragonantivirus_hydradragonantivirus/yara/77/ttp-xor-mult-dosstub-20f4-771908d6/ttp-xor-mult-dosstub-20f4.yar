rule TTP_XOR_MULT_DOSStub_20f4 {
  strings:
    $key_20f4 = { 74 9c [2] 00 84 [2] 47 86 [2] 00 97 [2] 4e 9b [2] 42 91 [2] 55 9a [2] 4e d4 [2] 73 }

  condition:
    any of them
}