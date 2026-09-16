rule TTP_XOR_MULT_DOSStub_3865 {
  strings:
    $key_3865 = { 6c 0d [2] 18 15 [2] 5f 17 [2] 18 06 [2] 56 0a [2] 5a 00 [2] 4d 0b [2] 56 45 [2] 6b }

  condition:
    any of them
}