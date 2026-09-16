rule TTP_XOR_MULT_DOSStub_4475 {
  strings:
    $key_4475 = { 10 1d [2] 64 05 [2] 23 07 [2] 64 16 [2] 2a 1a [2] 26 10 [2] 31 1b [2] 2a 55 [2] 17 }

  condition:
    any of them
}