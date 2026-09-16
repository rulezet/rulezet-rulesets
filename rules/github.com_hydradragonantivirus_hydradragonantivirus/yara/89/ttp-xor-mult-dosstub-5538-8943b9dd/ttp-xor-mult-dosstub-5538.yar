rule TTP_XOR_MULT_DOSStub_5538 {
  strings:
    $key_5538 = { 01 50 [2] 75 48 [2] 32 4a [2] 75 5b [2] 3b 57 [2] 37 5d [2] 20 56 [2] 3b 18 [2] 06 }

  condition:
    any of them
}