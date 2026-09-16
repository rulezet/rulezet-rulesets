rule TTP_XOR_MULT_DOSStub_73f2 {
  strings:
    $key_73f2 = { 27 9a [2] 53 82 [2] 14 80 [2] 53 91 [2] 1d 9d [2] 11 97 [2] 06 9c [2] 1d d2 [2] 20 }

  condition:
    any of them
}