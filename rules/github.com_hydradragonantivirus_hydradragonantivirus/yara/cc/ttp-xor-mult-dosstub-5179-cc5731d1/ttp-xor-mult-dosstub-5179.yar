rule TTP_XOR_MULT_DOSStub_5179 {
  strings:
    $key_5179 = { 05 11 [2] 71 09 [2] 36 0b [2] 71 1a [2] 3f 16 [2] 33 1c [2] 24 17 [2] 3f 59 [2] 02 }

  condition:
    any of them
}