rule TTP_XOR_MULT_DOSStub_1673 {
  strings:
    $key_1673 = { 42 1b [2] 36 03 [2] 71 01 [2] 36 10 [2] 78 1c [2] 74 16 [2] 63 1d [2] 78 53 [2] 45 }

  condition:
    any of them
}