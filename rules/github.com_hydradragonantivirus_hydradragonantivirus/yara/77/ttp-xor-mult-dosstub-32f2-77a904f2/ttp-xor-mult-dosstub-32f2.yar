rule TTP_XOR_MULT_DOSStub_32f2 {
  strings:
    $key_32f2 = { 66 9a [2] 12 82 [2] 55 80 [2] 12 91 [2] 5c 9d [2] 50 97 [2] 47 9c [2] 5c d2 [2] 61 }

  condition:
    any of them
}