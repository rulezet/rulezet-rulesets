rule TTP_XOR_MULT_DOSStub_0275 {
  strings:
    $key_0275 = { 56 1d [2] 22 05 [2] 65 07 [2] 22 16 [2] 6c 1a [2] 60 10 [2] 77 1b [2] 6c 55 [2] 51 }

  condition:
    any of them
}