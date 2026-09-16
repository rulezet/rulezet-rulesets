rule TTP_XOR_MULT_DOSStub_5473 {
  strings:
    $key_5473 = { 00 1b [2] 74 03 [2] 33 01 [2] 74 10 [2] 3a 1c [2] 36 16 [2] 21 1d [2] 3a 53 [2] 07 }

  condition:
    any of them
}