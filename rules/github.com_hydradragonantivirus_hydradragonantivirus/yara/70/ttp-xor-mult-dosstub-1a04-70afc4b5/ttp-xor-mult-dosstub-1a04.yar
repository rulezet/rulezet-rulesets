rule TTP_XOR_MULT_DOSStub_1a04 {
  strings:
    $key_1a04 = { 4e 6c [2] 3a 74 [2] 7d 76 [2] 3a 67 [2] 74 6b [2] 78 61 [2] 6f 6a [2] 74 24 [2] 49 }

  condition:
    any of them
}