rule TTP_XOR_MULT_DOSStub_55f9 {
  strings:
    $key_55f9 = { 01 91 [2] 75 89 [2] 32 8b [2] 75 9a [2] 3b 96 [2] 37 9c [2] 20 97 [2] 3b d9 [2] 06 }

  condition:
    any of them
}