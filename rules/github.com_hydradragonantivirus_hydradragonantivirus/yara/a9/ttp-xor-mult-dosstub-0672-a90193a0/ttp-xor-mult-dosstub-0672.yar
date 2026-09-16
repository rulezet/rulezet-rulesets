rule TTP_XOR_MULT_DOSStub_0672 {
  strings:
    $key_0672 = { 52 1a [2] 26 02 [2] 61 00 [2] 26 11 [2] 68 1d [2] 64 17 [2] 73 1c [2] 68 52 [2] 55 }

  condition:
    any of them
}