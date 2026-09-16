rule TTP_XOR_MULT_DOSStub_3072 {
  strings:
    $key_3072 = { 64 1a [2] 10 02 [2] 57 00 [2] 10 11 [2] 5e 1d [2] 52 17 [2] 45 1c [2] 5e 52 [2] 63 }

  condition:
    any of them
}