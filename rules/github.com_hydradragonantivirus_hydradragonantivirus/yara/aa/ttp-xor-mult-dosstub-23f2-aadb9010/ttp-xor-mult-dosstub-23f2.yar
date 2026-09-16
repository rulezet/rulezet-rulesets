rule TTP_XOR_MULT_DOSStub_23f2 {
  strings:
    $key_23f2 = { 77 9a [2] 03 82 [2] 44 80 [2] 03 91 [2] 4d 9d [2] 41 97 [2] 56 9c [2] 4d d2 [2] 70 }

  condition:
    any of them
}