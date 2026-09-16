rule TTP_XOR_MULT_DOSStub_2854 {
  strings:
    $key_2854 = { 7c 3c [2] 08 24 [2] 4f 26 [2] 08 37 [2] 46 3b [2] 4a 31 [2] 5d 3a [2] 46 74 [2] 7b }

  condition:
    any of them
}