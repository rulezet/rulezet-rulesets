rule TTP_XOR_MULT_DOSStub_40f4 {
  strings:
    $key_40f4 = { 14 9c [2] 60 84 [2] 27 86 [2] 60 97 [2] 2e 9b [2] 22 91 [2] 35 9a [2] 2e d4 [2] 13 }

  condition:
    any of them
}