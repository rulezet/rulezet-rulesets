rule TTP_XOR_MULT_DOSStub_1778 {
  strings:
    $key_1778 = { 43 10 [2] 37 08 [2] 70 0a [2] 37 1b [2] 79 17 [2] 75 1d [2] 62 16 [2] 79 58 [2] 44 }

  condition:
    any of them
}