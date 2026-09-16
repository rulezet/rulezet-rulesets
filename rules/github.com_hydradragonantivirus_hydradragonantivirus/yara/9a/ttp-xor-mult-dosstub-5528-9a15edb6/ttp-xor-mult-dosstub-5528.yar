rule TTP_XOR_MULT_DOSStub_5528 {
  strings:
    $key_5528 = { 01 40 [2] 75 58 [2] 32 5a [2] 75 4b [2] 3b 47 [2] 37 4d [2] 20 46 [2] 3b 08 [2] 06 }

  condition:
    any of them
}