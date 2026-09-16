rule TTP_XOR_MULT_DOSStub_0a75 {
  strings:
    $key_0a75 = { 5e 1d [2] 2a 05 [2] 6d 07 [2] 2a 16 [2] 64 1a [2] 68 10 [2] 7f 1b [2] 64 55 [2] 59 }

  condition:
    any of them
}