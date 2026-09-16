rule TTP_XOR_MULT_DOSStub_40f9 {
  strings:
    $key_40f9 = { 14 91 [2] 60 89 [2] 27 8b [2] 60 9a [2] 2e 96 [2] 22 9c [2] 35 97 [2] 2e d9 [2] 13 }

  condition:
    any of them
}