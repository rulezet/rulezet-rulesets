rule TTP_XOR_MULT_DOSStub_4af4 {
  strings:
    $key_4af4 = { 1e 9c [2] 6a 84 [2] 2d 86 [2] 6a 97 [2] 24 9b [2] 28 91 [2] 3f 9a [2] 24 d4 [2] 19 }

  condition:
    any of them
}