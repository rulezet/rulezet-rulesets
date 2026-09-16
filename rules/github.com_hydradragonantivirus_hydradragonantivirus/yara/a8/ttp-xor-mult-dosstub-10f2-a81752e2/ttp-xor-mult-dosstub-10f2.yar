rule TTP_XOR_MULT_DOSStub_10f2 {
  strings:
    $key_10f2 = { 44 9a [2] 30 82 [2] 77 80 [2] 30 91 [2] 7e 9d [2] 72 97 [2] 65 9c [2] 7e d2 [2] 43 }

  condition:
    any of them
}