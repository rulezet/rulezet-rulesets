rule TTP_XOR_MULT_DOSStub_0763 {
  strings:
    $key_0763 = { 53 0b [2] 27 13 [2] 60 11 [2] 27 00 [2] 69 0c [2] 65 06 [2] 72 0d [2] 69 43 [2] 54 }

  condition:
    any of them
}