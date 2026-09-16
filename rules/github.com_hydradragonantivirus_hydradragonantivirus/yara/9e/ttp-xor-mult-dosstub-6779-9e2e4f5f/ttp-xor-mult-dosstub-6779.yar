rule TTP_XOR_MULT_DOSStub_6779 {
  strings:
    $key_6779 = { 33 11 [2] 47 09 [2] 00 0b [2] 47 1a [2] 09 16 [2] 05 1c [2] 12 17 [2] 09 59 [2] 34 }

  condition:
    any of them
}