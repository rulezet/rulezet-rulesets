rule TTP_XOR_MULT_DOSStub_2644 {
  strings:
    $key_2644 = { 72 2c [2] 06 34 [2] 41 36 [2] 06 27 [2] 48 2b [2] 44 21 [2] 53 2a [2] 48 64 [2] 75 }

  condition:
    any of them
}