rule TTP_XOR_MULT_DOSStub_6703 {
  strings:
    $key_6703 = { 33 6b [2] 47 73 [2] 00 71 [2] 47 60 [2] 09 6c [2] 05 66 [2] 12 6d [2] 09 23 [2] 34 }

  condition:
    any of them
}