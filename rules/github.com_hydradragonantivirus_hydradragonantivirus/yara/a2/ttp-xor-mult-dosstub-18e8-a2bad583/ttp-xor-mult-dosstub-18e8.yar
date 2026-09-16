rule TTP_XOR_MULT_DOSStub_18e8 {
  strings:
    $key_18e8 = { 4c 80 [2] 38 98 [2] 7f 9a [2] 38 8b [2] 76 87 [2] 7a 8d [2] 6d 86 [2] 76 c8 [2] 4b }

  condition:
    any of them
}