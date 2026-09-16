rule TTP_XOR_MULT_DOSStub_46f2 {
  strings:
    $key_46f2 = { 12 9a [2] 66 82 [2] 21 80 [2] 66 91 [2] 28 9d [2] 24 97 [2] 33 9c [2] 28 d2 [2] 15 }

  condition:
    any of them
}