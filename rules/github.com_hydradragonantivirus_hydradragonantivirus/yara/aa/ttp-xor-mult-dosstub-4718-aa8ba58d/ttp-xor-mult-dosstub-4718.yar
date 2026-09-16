rule TTP_XOR_MULT_DOSStub_4718 {
  strings:
    $key_4718 = { 13 70 [2] 67 68 [2] 20 6a [2] 67 7b [2] 29 77 [2] 25 7d [2] 32 76 [2] 29 38 [2] 14 }

  condition:
    any of them
}