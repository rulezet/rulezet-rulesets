rule TTP_XOR_MULT_DOSStub_6308 {
  strings:
    $key_6308 = { 37 60 [2] 43 78 [2] 04 7a [2] 43 6b [2] 0d 67 [2] 01 6d [2] 16 66 [2] 0d 28 [2] 30 }

  condition:
    any of them
}