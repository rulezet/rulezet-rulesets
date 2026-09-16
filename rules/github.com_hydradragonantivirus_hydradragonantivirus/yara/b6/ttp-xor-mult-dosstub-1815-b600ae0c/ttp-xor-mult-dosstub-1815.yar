rule TTP_XOR_MULT_DOSStub_1815 {
  strings:
    $key_1815 = { 4c 7d [2] 38 65 [2] 7f 67 [2] 38 76 [2] 76 7a [2] 7a 70 [2] 6d 7b [2] 76 35 [2] 4b }

  condition:
    any of them
}