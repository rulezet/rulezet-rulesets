rule TTP_XOR_MULT_DOSStub_0679 {
  strings:
    $key_0679 = { 52 11 [2] 26 09 [2] 61 0b [2] 26 1a [2] 68 16 [2] 64 1c [2] 73 17 [2] 68 59 [2] 55 }

  condition:
    any of them
}