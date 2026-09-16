rule TTP_XOR_MULT_DOSStub_4af9 {
  strings:
    $key_4af9 = { 1e 91 [2] 6a 89 [2] 2d 8b [2] 6a 9a [2] 24 96 [2] 28 9c [2] 3f 97 [2] 24 d9 [2] 19 }

  condition:
    any of them
}