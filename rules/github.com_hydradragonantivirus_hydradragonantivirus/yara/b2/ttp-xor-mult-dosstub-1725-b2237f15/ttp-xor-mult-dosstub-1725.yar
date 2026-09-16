rule TTP_XOR_MULT_DOSStub_1725 {
  strings:
    $key_1725 = { 43 4d [2] 37 55 [2] 70 57 [2] 37 46 [2] 79 4a [2] 75 40 [2] 62 4b [2] 79 05 [2] 44 }

  condition:
    any of them
}