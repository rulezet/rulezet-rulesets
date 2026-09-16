rule TTP_XOR_MULT_DOSStub_78f4 {
  strings:
    $key_78f4 = { 2c 9c [2] 58 84 [2] 1f 86 [2] 58 97 [2] 16 9b [2] 1a 91 [2] 0d 9a [2] 16 d4 [2] 2b }

  condition:
    any of them
}