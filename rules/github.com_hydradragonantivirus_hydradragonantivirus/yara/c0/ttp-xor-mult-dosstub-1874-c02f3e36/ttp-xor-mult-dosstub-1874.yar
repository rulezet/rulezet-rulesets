rule TTP_XOR_MULT_DOSStub_1874 {
  strings:
    $key_1874 = { 4c 1c [2] 38 04 [2] 7f 06 [2] 38 17 [2] 76 1b [2] 7a 11 [2] 6d 1a [2] 76 54 [2] 4b }

  condition:
    any of them
}