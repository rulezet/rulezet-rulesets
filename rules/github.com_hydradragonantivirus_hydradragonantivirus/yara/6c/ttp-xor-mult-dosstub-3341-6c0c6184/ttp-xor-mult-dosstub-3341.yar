rule TTP_XOR_MULT_DOSStub_3341 {
  strings:
    $key_3341 = { 67 29 [2] 13 31 [2] 54 33 [2] 13 22 [2] 5d 2e [2] 51 24 [2] 46 2f [2] 5d 61 [2] 60 }

  condition:
    any of them
}