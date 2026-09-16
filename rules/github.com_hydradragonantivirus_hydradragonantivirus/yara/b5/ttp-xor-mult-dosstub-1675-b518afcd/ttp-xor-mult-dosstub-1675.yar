rule TTP_XOR_MULT_DOSStub_1675 {
  strings:
    $key_1675 = { 42 1d [2] 36 05 [2] 71 07 [2] 36 16 [2] 78 1a [2] 74 10 [2] 63 1b [2] 78 55 [2] 45 }

  condition:
    any of them
}