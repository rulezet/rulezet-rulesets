rule TTP_XOR_MULT_DOSStub_6635 {
  strings:
    $key_6635 = { 32 5d [2] 46 45 [2] 01 47 [2] 46 56 [2] 08 5a [2] 04 50 [2] 13 5b [2] 08 15 [2] 35 }

  condition:
    any of them
}