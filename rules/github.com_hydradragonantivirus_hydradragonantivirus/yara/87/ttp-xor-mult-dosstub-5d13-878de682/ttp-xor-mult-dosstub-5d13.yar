rule TTP_XOR_MULT_DOSStub_5d13 {
  strings:
    $key_5d13 = { 09 7b [2] 7d 63 [2] 3a 61 [2] 7d 70 [2] 33 7c [2] 3f 76 [2] 28 7d [2] 33 33 [2] 0e }

  condition:
    any of them
}