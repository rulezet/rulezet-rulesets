rule TTP_XOR_MULT_DOSStub_3b72 {
  strings:
    $key_3b72 = { 6f 1a [2] 1b 02 [2] 5c 00 [2] 1b 11 [2] 55 1d [2] 59 17 [2] 4e 1c [2] 55 52 [2] 68 }

  condition:
    any of them
}