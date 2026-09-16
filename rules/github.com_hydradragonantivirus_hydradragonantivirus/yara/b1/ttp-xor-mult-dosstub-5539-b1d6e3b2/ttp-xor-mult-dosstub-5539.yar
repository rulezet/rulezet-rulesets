rule TTP_XOR_MULT_DOSStub_5539 {
  strings:
    $key_5539 = { 01 51 [2] 75 49 [2] 32 4b [2] 75 5a [2] 3b 56 [2] 37 5c [2] 20 57 [2] 3b 19 [2] 06 }

  condition:
    any of them
}