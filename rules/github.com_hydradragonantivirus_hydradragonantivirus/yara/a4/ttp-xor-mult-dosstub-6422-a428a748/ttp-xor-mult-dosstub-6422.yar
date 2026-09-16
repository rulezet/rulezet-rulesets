rule TTP_XOR_MULT_DOSStub_6422 {
  strings:
    $key_6422 = { 30 4a [2] 44 52 [2] 03 50 [2] 44 41 [2] 0a 4d [2] 06 47 [2] 11 4c [2] 0a 02 [2] 37 }

  condition:
    any of them
}