rule TTP_XOR_MULT_DOSStub_12f2 {
  strings:
    $key_12f2 = { 46 9a [2] 32 82 [2] 75 80 [2] 32 91 [2] 7c 9d [2] 70 97 [2] 67 9c [2] 7c d2 [2] 41 }

  condition:
    any of them
}