rule TTP_XOR_MULT_DOSStub_7779 {
  strings:
    $key_7779 = { 23 11 [2] 57 09 [2] 10 0b [2] 57 1a [2] 19 16 [2] 15 1c [2] 02 17 [2] 19 59 [2] 24 }

  condition:
    any of them
}