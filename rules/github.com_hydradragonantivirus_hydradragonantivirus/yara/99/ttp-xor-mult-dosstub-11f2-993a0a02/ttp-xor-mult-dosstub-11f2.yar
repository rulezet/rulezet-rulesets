rule TTP_XOR_MULT_DOSStub_11f2 {
  strings:
    $key_11f2 = { 45 9a [2] 31 82 [2] 76 80 [2] 31 91 [2] 7f 9d [2] 73 97 [2] 64 9c [2] 7f d2 [2] 42 }

  condition:
    any of them
}