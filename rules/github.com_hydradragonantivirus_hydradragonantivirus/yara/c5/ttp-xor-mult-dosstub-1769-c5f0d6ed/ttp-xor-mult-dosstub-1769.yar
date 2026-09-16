rule TTP_XOR_MULT_DOSStub_1769 {
  strings:
    $key_1769 = { 43 01 [2] 37 19 [2] 70 1b [2] 37 0a [2] 79 06 [2] 75 0c [2] 62 07 [2] 79 49 [2] 44 }

  condition:
    any of them
}