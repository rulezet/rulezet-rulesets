rule TTP_XOR_MULT_DOSStub_1af2 {
  strings:
    $key_1af2 = { 4e 9a [2] 3a 82 [2] 7d 80 [2] 3a 91 [2] 74 9d [2] 78 97 [2] 6f 9c [2] 74 d2 [2] 49 }

  condition:
    any of them
}