rule TTP_XOR_MULT_DOSStub_2664 {
  strings:
    $key_2664 = { 72 0c [2] 06 14 [2] 41 16 [2] 06 07 [2] 48 0b [2] 44 01 [2] 53 0a [2] 48 44 [2] 75 }

  condition:
    any of them
}