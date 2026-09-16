rule TTP_XOR_MULT_DOSStub_3af4 {
  strings:
    $key_3af4 = { 6e 9c [2] 1a 84 [2] 5d 86 [2] 1a 97 [2] 54 9b [2] 58 91 [2] 4f 9a [2] 54 d4 [2] 69 }

  condition:
    any of them
}