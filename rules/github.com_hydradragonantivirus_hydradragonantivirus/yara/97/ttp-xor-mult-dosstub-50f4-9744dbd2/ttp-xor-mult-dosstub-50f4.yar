rule TTP_XOR_MULT_DOSStub_50f4 {
  strings:
    $key_50f4 = { 04 9c [2] 70 84 [2] 37 86 [2] 70 97 [2] 3e 9b [2] 32 91 [2] 25 9a [2] 3e d4 [2] 03 }

  condition:
    any of them
}