rule TTP_XOR_MULT_DOSStub_6cf9 {
  strings:
    $key_6cf9 = { 38 91 [2] 4c 89 [2] 0b 8b [2] 4c 9a [2] 02 96 [2] 0e 9c [2] 19 97 [2] 02 d9 [2] 3f }

  condition:
    any of them
}