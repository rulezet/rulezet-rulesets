rule TTP_XOR_MULT_DOSStub_7673 {
  strings:
    $key_7673 = { 22 1b [2] 56 03 [2] 11 01 [2] 56 10 [2] 18 1c [2] 14 16 [2] 03 1d [2] 18 53 [2] 25 }

  condition:
    any of them
}