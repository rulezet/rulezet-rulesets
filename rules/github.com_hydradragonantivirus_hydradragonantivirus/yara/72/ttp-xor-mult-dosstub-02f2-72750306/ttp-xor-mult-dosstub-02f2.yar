rule TTP_XOR_MULT_DOSStub_02f2 {
  strings:
    $key_02f2 = { 56 9a [2] 22 82 [2] 65 80 [2] 22 91 [2] 6c 9d [2] 60 97 [2] 77 9c [2] 6c d2 [2] 51 }

  condition:
    any of them
}