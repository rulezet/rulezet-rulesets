rule TTP_XOR_MULT_DOSStub_6738 {
  strings:
    $key_6738 = { 33 50 [2] 47 48 [2] 00 4a [2] 47 5b [2] 09 57 [2] 05 5d [2] 12 56 [2] 09 18 [2] 34 }

  condition:
    any of them
}