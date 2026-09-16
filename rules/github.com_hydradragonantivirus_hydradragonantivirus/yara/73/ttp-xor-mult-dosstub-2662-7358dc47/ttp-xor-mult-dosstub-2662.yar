rule TTP_XOR_MULT_DOSStub_2662 {
  strings:
    $key_2662 = { 72 0a [2] 06 12 [2] 41 10 [2] 06 01 [2] 48 0d [2] 44 07 [2] 53 0c [2] 48 42 [2] 75 }

  condition:
    any of them
}