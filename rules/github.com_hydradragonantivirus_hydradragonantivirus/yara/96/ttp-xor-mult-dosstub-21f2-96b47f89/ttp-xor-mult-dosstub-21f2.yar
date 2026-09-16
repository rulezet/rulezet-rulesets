rule TTP_XOR_MULT_DOSStub_21f2 {
  strings:
    $key_21f2 = { 75 9a [2] 01 82 [2] 46 80 [2] 01 91 [2] 4f 9d [2] 43 97 [2] 54 9c [2] 4f d2 [2] 72 }

  condition:
    any of them
}