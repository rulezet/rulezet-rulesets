rule TTP_XOR_MULT_DOSStub_6718 {
  strings:
    $key_6718 = { 33 70 [2] 47 68 [2] 00 6a [2] 47 7b [2] 09 77 [2] 05 7d [2] 12 76 [2] 09 38 [2] 34 }

  condition:
    any of them
}