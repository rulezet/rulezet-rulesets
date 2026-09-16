rule TTP_XOR_MULT_DOSStub_2cf4 {
  strings:
    $key_2cf4 = { 78 9c [2] 0c 84 [2] 4b 86 [2] 0c 97 [2] 42 9b [2] 4e 91 [2] 59 9a [2] 42 d4 [2] 7f }

  condition:
    any of them
}