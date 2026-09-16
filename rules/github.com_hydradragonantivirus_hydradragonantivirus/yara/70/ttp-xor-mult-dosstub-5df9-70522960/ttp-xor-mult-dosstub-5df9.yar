rule TTP_XOR_MULT_DOSStub_5df9 {
  strings:
    $key_5df9 = { 09 91 [2] 7d 89 [2] 3a 8b [2] 7d 9a [2] 33 96 [2] 3f 9c [2] 28 97 [2] 33 d9 [2] 0e }

  condition:
    any of them
}