rule TTP_XOR_MULT_DOSStub_4d72 {
  strings:
    $key_4d72 = { 19 1a [2] 6d 02 [2] 2a 00 [2] 6d 11 [2] 23 1d [2] 2f 17 [2] 38 1c [2] 23 52 [2] 1e }

  condition:
    any of them
}