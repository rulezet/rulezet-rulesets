rule TTP_XOR_MULT_DOSStub_27f2 {
  strings:
    $key_27f2 = { 73 9a [2] 07 82 [2] 40 80 [2] 07 91 [2] 49 9d [2] 45 97 [2] 52 9c [2] 49 d2 [2] 74 }

  condition:
    any of them
}