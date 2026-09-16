rule TTP_XOR_MULT_DOSStub_64f4 {
  strings:
    $key_64f4 = { 30 9c [2] 44 84 [2] 03 86 [2] 44 97 [2] 0a 9b [2] 06 91 [2] 11 9a [2] 0a d4 [2] 37 }

  condition:
    any of them
}