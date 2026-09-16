rule TTP_XOR_MULT_DOSStub_4d18 {
  strings:
    $key_4d18 = { 19 70 [2] 6d 68 [2] 2a 6a [2] 6d 7b [2] 23 77 [2] 2f 7d [2] 38 76 [2] 23 38 [2] 1e }

  condition:
    any of them
}