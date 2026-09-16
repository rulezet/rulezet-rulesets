rule TTP_XOR_MULT_DOSStub_0464 {
  strings:
    $key_0464 = { 50 0c [2] 24 14 [2] 63 16 [2] 24 07 [2] 6a 0b [2] 66 01 [2] 71 0a [2] 6a 44 [2] 57 }

  condition:
    any of them
}