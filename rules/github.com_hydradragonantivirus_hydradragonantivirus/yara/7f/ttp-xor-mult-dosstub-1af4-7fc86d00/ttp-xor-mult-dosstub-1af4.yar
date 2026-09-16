rule TTP_XOR_MULT_DOSStub_1af4 {
  strings:
    $key_1af4 = { 4e 9c [2] 3a 84 [2] 7d 86 [2] 3a 97 [2] 74 9b [2] 78 91 [2] 6f 9a [2] 74 d4 [2] 49 }

  condition:
    any of them
}