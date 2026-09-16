rule TTP_XOR_MULT_DOSStub_41f4 {
  strings:
    $key_41f4 = { 15 9c [2] 61 84 [2] 26 86 [2] 61 97 [2] 2f 9b [2] 23 91 [2] 34 9a [2] 2f d4 [2] 12 }

  condition:
    any of them
}