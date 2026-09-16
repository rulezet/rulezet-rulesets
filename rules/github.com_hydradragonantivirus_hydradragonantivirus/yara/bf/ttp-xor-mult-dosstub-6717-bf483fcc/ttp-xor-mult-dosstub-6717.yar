rule TTP_XOR_MULT_DOSStub_6717 {
  strings:
    $key_6717 = { 33 7f [2] 47 67 [2] 00 65 [2] 47 74 [2] 09 78 [2] 05 72 [2] 12 79 [2] 09 37 [2] 34 }

  condition:
    any of them
}