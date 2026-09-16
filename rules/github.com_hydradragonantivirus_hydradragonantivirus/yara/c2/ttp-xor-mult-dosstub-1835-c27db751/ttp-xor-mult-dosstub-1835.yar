rule TTP_XOR_MULT_DOSStub_1835 {
  strings:
    $key_1835 = { 4c 5d [2] 38 45 [2] 7f 47 [2] 38 56 [2] 76 5a [2] 7a 50 [2] 6d 5b [2] 76 15 [2] 4b }

  condition:
    any of them
}