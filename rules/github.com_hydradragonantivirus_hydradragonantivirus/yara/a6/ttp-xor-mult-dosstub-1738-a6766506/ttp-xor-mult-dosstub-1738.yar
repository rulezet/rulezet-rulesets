rule TTP_XOR_MULT_DOSStub_1738 {
  strings:
    $key_1738 = { 43 50 [2] 37 48 [2] 70 4a [2] 37 5b [2] 79 57 [2] 75 5d [2] 62 56 [2] 79 18 [2] 44 }

  condition:
    any of them
}