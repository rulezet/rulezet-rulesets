rule TTP_XOR_MULT_DOSStub_1678 {
  strings:
    $key_1678 = { 42 10 [2] 36 08 [2] 71 0a [2] 36 1b [2] 78 17 [2] 74 1d [2] 63 16 [2] 78 58 [2] 45 }

  condition:
    any of them
}