rule TTP_XOR_MULT_DOSStub_1172 {
  strings:
    $key_1172 = { 45 1a [2] 31 02 [2] 76 00 [2] 31 11 [2] 7f 1d [2] 73 17 [2] 64 1c [2] 7f 52 [2] 42 }

  condition:
    any of them
}