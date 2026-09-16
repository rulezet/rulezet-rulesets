rule TTP_XOR_MULT_DOSStub_7438 {
  strings:
    $key_7438 = { 20 50 [2] 54 48 [2] 13 4a [2] 54 5b [2] 1a 57 [2] 16 5d [2] 01 56 [2] 1a 18 [2] 27 }

  condition:
    any of them
}