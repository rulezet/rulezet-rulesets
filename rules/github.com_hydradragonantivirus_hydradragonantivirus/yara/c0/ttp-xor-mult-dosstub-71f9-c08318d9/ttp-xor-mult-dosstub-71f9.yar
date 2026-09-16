rule TTP_XOR_MULT_DOSStub_71f9 {
  strings:
    $key_71f9 = { 25 91 [2] 51 89 [2] 16 8b [2] 51 9a [2] 1f 96 [2] 13 9c [2] 04 97 [2] 1f d9 [2] 22 }

  condition:
    any of them
}