rule TTP_XOR_MULT_DOSStub_3663 {
  strings:
    $key_3663 = { 62 0b [2] 16 13 [2] 51 11 [2] 16 00 [2] 58 0c [2] 54 06 [2] 43 0d [2] 58 43 [2] 65 }

  condition:
    any of them
}