rule TTP_XOR_MULT_DOSStub_2af2 {
  strings:
    $key_2af2 = { 7e 9a [2] 0a 82 [2] 4d 80 [2] 0a 91 [2] 44 9d [2] 48 97 [2] 5f 9c [2] 44 d2 [2] 79 }

  condition:
    any of them
}