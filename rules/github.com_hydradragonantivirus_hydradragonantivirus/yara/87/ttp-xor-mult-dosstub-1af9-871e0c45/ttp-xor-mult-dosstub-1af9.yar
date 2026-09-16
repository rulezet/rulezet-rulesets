rule TTP_XOR_MULT_DOSStub_1af9 {
  strings:
    $key_1af9 = { 4e 91 [2] 3a 89 [2] 7d 8b [2] 3a 9a [2] 74 96 [2] 78 9c [2] 6f 97 [2] 74 d9 [2] 49 }

  condition:
    any of them
}