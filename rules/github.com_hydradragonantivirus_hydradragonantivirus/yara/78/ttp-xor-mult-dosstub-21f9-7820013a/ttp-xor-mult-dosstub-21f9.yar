rule TTP_XOR_MULT_DOSStub_21f9 {
  strings:
    $key_21f9 = { 75 91 [2] 01 89 [2] 46 8b [2] 01 9a [2] 4f 96 [2] 43 9c [2] 54 97 [2] 4f d9 [2] 72 }

  condition:
    any of them
}