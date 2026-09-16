rule TTP_XOR_MULT_DOSStub_5d09 {
  strings:
    $key_5d09 = { 09 61 [2] 7d 79 [2] 3a 7b [2] 7d 6a [2] 33 66 [2] 3f 6c [2] 28 67 [2] 33 29 [2] 0e }

  condition:
    any of them
}