rule TTP_XOR_MULT_DOSStub_52f2 {
  strings:
    $key_52f2 = { 06 9a [2] 72 82 [2] 35 80 [2] 72 91 [2] 3c 9d [2] 30 97 [2] 27 9c [2] 3c d2 [2] 01 }

  condition:
    any of them
}