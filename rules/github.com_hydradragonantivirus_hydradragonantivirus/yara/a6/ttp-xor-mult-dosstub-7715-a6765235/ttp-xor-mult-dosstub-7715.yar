rule TTP_XOR_MULT_DOSStub_7715 {
  strings:
    $key_7715 = { 23 7d [2] 57 65 [2] 10 67 [2] 57 76 [2] 19 7a [2] 15 70 [2] 02 7b [2] 19 35 [2] 24 }

  condition:
    any of them
}