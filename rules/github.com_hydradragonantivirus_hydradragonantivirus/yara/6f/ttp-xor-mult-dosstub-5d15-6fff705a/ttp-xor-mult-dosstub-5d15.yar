rule TTP_XOR_MULT_DOSStub_5d15 {
  strings:
    $key_5d15 = { 09 7d [2] 7d 65 [2] 3a 67 [2] 7d 76 [2] 33 7a [2] 3f 70 [2] 28 7b [2] 33 35 [2] 0e }

  condition:
    any of them
}