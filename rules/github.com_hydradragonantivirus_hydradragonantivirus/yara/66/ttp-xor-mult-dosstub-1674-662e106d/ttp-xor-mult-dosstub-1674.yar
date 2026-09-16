rule TTP_XOR_MULT_DOSStub_1674 {
  strings:
    $key_1674 = { 42 1c [2] 36 04 [2] 71 06 [2] 36 17 [2] 78 1b [2] 74 11 [2] 63 1a [2] 78 54 [2] 45 }

  condition:
    any of them
}