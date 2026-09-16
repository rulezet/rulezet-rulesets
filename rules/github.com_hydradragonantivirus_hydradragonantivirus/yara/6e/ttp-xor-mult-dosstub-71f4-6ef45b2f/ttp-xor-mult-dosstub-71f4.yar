rule TTP_XOR_MULT_DOSStub_71f4 {
  strings:
    $key_71f4 = { 25 9c [2] 51 84 [2] 16 86 [2] 51 97 [2] 1f 9b [2] 13 91 [2] 04 9a [2] 1f d4 [2] 22 }

  condition:
    any of them
}