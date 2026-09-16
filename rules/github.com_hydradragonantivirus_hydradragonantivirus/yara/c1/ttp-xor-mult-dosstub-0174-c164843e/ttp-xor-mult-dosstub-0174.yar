rule TTP_XOR_MULT_DOSStub_0174 {
  strings:
    $key_0174 = { 55 1c [2] 21 04 [2] 66 06 [2] 21 17 [2] 6f 1b [2] 63 11 [2] 74 1a [2] 6f 54 [2] 52 }

  condition:
    any of them
}