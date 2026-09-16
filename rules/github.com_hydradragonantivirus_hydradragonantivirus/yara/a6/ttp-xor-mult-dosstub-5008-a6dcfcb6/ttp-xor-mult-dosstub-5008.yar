rule TTP_XOR_MULT_DOSStub_5008 {
  strings:
    $key_5008 = { 04 60 [2] 70 78 [2] 37 7a [2] 70 6b [2] 3e 67 [2] 32 6d [2] 25 66 [2] 3e 28 [2] 03 }

  condition:
    any of them
}