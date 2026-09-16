rule TTP_XOR_MULT_DOSStub_5679 {
  strings:
    $key_5679 = { 02 11 [2] 76 09 [2] 31 0b [2] 76 1a [2] 38 16 [2] 34 1c [2] 23 17 [2] 38 59 [2] 05 }

  condition:
    any of them
}