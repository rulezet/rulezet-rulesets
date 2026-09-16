rule TTP_XOR_MULT_DOSStub_2208 {
  strings:
    $key_2208 = { 76 60 [2] 02 78 [2] 45 7a [2] 02 6b [2] 4c 67 [2] 40 6d [2] 57 66 [2] 4c 28 [2] 71 }

  condition:
    any of them
}