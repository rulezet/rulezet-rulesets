rule TTP_XOR_MULT_DOSStub_6408 {
  strings:
    $key_6408 = { 30 60 [2] 44 78 [2] 03 7a [2] 44 6b [2] 0a 67 [2] 06 6d [2] 11 66 [2] 0a 28 [2] 37 }

  condition:
    any of them
}