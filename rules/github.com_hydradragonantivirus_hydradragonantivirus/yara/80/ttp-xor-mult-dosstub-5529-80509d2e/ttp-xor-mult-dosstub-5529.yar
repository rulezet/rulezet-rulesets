rule TTP_XOR_MULT_DOSStub_5529 {
  strings:
    $key_5529 = { 01 41 [2] 75 59 [2] 32 5b [2] 75 4a [2] 3b 46 [2] 37 4c [2] 20 47 [2] 3b 09 [2] 06 }

  condition:
    any of them
}