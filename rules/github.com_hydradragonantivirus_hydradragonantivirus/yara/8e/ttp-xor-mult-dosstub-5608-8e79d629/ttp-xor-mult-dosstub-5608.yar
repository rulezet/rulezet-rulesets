rule TTP_XOR_MULT_DOSStub_5608 {
  strings:
    $key_5608 = { 02 60 [2] 76 78 [2] 31 7a [2] 76 6b [2] 38 67 [2] 34 6d [2] 23 66 [2] 38 28 [2] 05 }

  condition:
    any of them
}