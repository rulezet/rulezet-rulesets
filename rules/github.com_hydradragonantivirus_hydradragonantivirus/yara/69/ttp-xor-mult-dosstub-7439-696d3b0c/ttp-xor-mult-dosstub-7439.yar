rule TTP_XOR_MULT_DOSStub_7439 {
  strings:
    $key_7439 = { 20 51 [2] 54 49 [2] 13 4b [2] 54 5a [2] 1a 56 [2] 16 5c [2] 01 57 [2] 1a 19 [2] 27 }

  condition:
    any of them
}