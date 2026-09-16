rule TTP_XOR_MULT_DOSStub_1a15 {
  strings:
    $key_1a15 = { 4e 7d [2] 3a 65 [2] 7d 67 [2] 3a 76 [2] 74 7a [2] 78 70 [2] 6f 7b [2] 74 35 [2] 49 }

  condition:
    any of them
}