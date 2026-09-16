rule TTP_XOR_MULT_DOSStub_1879 {
  strings:
    $key_1879 = { 4c 11 [2] 38 09 [2] 7f 0b [2] 38 1a [2] 76 16 [2] 7a 1c [2] 6d 17 [2] 76 59 [2] 4b }

  condition:
    any of them
}