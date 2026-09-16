rule TTP_XOR_MULT_DOSStub_1a64 {
  strings:
    $key_1a64 = { 4e 0c [2] 3a 14 [2] 7d 16 [2] 3a 07 [2] 74 0b [2] 78 01 [2] 6f 0a [2] 74 44 [2] 49 }

  condition:
    any of them
}