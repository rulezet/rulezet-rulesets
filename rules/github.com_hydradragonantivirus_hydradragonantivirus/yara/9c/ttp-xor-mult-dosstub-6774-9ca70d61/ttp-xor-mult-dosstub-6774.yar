rule TTP_XOR_MULT_DOSStub_6774 {
  strings:
    $key_6774 = { 33 1c [2] 47 04 [2] 00 06 [2] 47 17 [2] 09 1b [2] 05 11 [2] 12 1a [2] 09 54 [2] 34 }

  condition:
    any of them
}