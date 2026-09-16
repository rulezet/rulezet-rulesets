rule TTP_XOR_MULT_DOSStub_1af5 {
  strings:
    $key_1af5 = { 4e 9d [2] 3a 85 [2] 7d 87 [2] 3a 96 [2] 74 9a [2] 78 90 [2] 6f 9b [2] 74 d5 [2] 49 }

  condition:
    any of them
}