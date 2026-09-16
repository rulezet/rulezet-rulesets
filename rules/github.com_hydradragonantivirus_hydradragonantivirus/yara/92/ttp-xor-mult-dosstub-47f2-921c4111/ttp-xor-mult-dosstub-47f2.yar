rule TTP_XOR_MULT_DOSStub_47f2 {
  strings:
    $key_47f2 = { 13 9a [2] 67 82 [2] 20 80 [2] 67 91 [2] 29 9d [2] 25 97 [2] 32 9c [2] 29 d2 [2] 14 }

  condition:
    any of them
}