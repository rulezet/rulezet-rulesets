rule TTP_XOR_MULT_DOSStub_6415 {
  strings:
    $key_6415 = { 30 7d [2] 44 65 [2] 03 67 [2] 44 76 [2] 0a 7a [2] 06 70 [2] 11 7b [2] 0a 35 [2] 37 }

  condition:
    any of them
}