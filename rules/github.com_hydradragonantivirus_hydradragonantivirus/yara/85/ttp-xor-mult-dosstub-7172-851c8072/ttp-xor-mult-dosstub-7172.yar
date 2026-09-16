rule TTP_XOR_MULT_DOSStub_7172 {
  strings:
    $key_7172 = { 25 1a [2] 51 02 [2] 16 00 [2] 51 11 [2] 1f 1d [2] 13 17 [2] 04 1c [2] 1f 52 [2] 22 }

  condition:
    any of them
}