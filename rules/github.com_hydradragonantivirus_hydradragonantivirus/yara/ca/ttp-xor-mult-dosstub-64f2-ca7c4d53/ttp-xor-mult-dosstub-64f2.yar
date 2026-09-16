rule TTP_XOR_MULT_DOSStub_64f2 {
  strings:
    $key_64f2 = { 30 9a [2] 44 82 [2] 03 80 [2] 44 91 [2] 0a 9d [2] 06 97 [2] 11 9c [2] 0a d2 [2] 37 }

  condition:
    any of them
}