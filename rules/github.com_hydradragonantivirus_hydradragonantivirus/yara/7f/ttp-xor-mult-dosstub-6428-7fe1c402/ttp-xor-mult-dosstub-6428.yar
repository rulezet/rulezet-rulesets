rule TTP_XOR_MULT_DOSStub_6428 {
  strings:
    $key_6428 = { 30 40 [2] 44 58 [2] 03 5a [2] 44 4b [2] 0a 47 [2] 06 4d [2] 11 46 [2] 0a 08 [2] 37 }

  condition:
    any of them
}