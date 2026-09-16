rule TTP_XOR_MULT_DOSStub_03f2 {
  strings:
    $key_03f2 = { 57 9a [2] 23 82 [2] 64 80 [2] 23 91 [2] 6d 9d [2] 61 97 [2] 76 9c [2] 6d d2 [2] 50 }

  condition:
    any of them
}