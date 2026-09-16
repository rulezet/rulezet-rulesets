rule TTP_XOR_MULT_DOSStub_5a64 {
  strings:
    $key_5a64 = { 0e 0c [2] 7a 14 [2] 3d 16 [2] 7a 07 [2] 34 0b [2] 38 01 [2] 2f 0a [2] 34 44 [2] 09 }

  condition:
    any of them
}