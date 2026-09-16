rule TTP_XOR_MULT_DOSStub_2418 {
  strings:
    $key_2418 = { 70 70 [2] 04 68 [2] 43 6a [2] 04 7b [2] 4a 77 [2] 46 7d [2] 51 76 [2] 4a 38 [2] 77 }

  condition:
    any of them
}