rule TTP_XOR_MULT_DOSStub_67f2 {
  strings:
    $key_67f2 = { 33 9a [2] 47 82 [2] 00 80 [2] 47 91 [2] 09 9d [2] 05 97 [2] 12 9c [2] 09 d2 [2] 34 }

  condition:
    any of them
}