rule TTP_XOR_MULT_DOSStub_77f4 {
  strings:
    $key_77f4 = { 23 9c [2] 57 84 [2] 10 86 [2] 57 97 [2] 19 9b [2] 15 91 [2] 02 9a [2] 19 d4 [2] 24 }

  condition:
    any of them
}