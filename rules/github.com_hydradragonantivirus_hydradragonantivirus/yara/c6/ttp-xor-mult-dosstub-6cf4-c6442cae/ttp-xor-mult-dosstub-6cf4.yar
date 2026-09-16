rule TTP_XOR_MULT_DOSStub_6cf4 {
  strings:
    $key_6cf4 = { 38 9c [2] 4c 84 [2] 0b 86 [2] 4c 97 [2] 02 9b [2] 0e 91 [2] 19 9a [2] 02 d4 [2] 3f }

  condition:
    any of them
}