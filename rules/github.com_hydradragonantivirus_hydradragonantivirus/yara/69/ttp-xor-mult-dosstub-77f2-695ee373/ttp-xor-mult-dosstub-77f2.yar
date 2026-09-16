rule TTP_XOR_MULT_DOSStub_77f2 {
  strings:
    $key_77f2 = { 23 9a [2] 57 82 [2] 10 80 [2] 57 91 [2] 19 9d [2] 15 97 [2] 02 9c [2] 19 d2 [2] 24 }

  condition:
    any of them
}