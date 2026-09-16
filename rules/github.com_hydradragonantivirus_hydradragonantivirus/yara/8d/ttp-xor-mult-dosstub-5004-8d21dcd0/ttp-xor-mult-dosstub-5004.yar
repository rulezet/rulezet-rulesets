rule TTP_XOR_MULT_DOSStub_5004 {
  strings:
    $key_5004 = { 04 6c [2] 70 74 [2] 37 76 [2] 70 67 [2] 3e 6b [2] 32 61 [2] 25 6a [2] 3e 24 [2] 03 }

  condition:
    any of them
}