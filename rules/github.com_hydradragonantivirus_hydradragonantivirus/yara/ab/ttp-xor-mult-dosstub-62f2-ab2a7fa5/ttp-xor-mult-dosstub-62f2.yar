rule TTP_XOR_MULT_DOSStub_62f2 {
  strings:
    $key_62f2 = { 36 9a [2] 42 82 [2] 05 80 [2] 42 91 [2] 0c 9d [2] 00 97 [2] 17 9c [2] 0c d2 [2] 31 }

  condition:
    any of them
}