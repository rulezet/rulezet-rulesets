rule TTP_XOR_MULT_DOSStub_5535 {
  strings:
    $key_5535 = { 01 5d [2] 75 45 [2] 32 47 [2] 75 56 [2] 3b 5a [2] 37 50 [2] 20 5b [2] 3b 15 [2] 06 }

  condition:
    any of them
}