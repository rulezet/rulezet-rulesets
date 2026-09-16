rule TTP_XOR_MULT_DOSStub_74f9 {
  strings:
    $key_74f9 = { 20 91 [2] 54 89 [2] 13 8b [2] 54 9a [2] 1a 96 [2] 16 9c [2] 01 97 [2] 1a d9 [2] 27 }

  condition:
    any of them
}