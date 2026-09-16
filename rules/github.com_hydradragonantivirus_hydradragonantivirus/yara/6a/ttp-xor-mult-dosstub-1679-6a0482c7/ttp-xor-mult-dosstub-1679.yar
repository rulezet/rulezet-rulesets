rule TTP_XOR_MULT_DOSStub_1679 {
  strings:
    $key_1679 = { 42 11 [2] 36 09 [2] 71 0b [2] 36 1a [2] 78 16 [2] 74 1c [2] 63 17 [2] 78 59 [2] 45 }

  condition:
    any of them
}