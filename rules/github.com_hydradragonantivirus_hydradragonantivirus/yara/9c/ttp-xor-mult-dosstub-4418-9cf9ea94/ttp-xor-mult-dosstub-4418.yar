rule TTP_XOR_MULT_DOSStub_4418 {
  strings:
    $key_4418 = { 10 70 [2] 64 68 [2] 23 6a [2] 64 7b [2] 2a 77 [2] 26 7d [2] 31 76 [2] 2a 38 [2] 17 }

  condition:
    any of them
}