rule TTP_XOR_MULT_DOSStub_7429 {
  strings:
    $key_7429 = { 20 41 [2] 54 59 [2] 13 5b [2] 54 4a [2] 1a 46 [2] 16 4c [2] 01 47 [2] 1a 09 [2] 27 }

  condition:
    any of them
}