rule TTP_XOR_MULT_DOSStub_4d25 {
  strings:
    $key_4d25 = { 19 4d [2] 6d 55 [2] 2a 57 [2] 6d 46 [2] 23 4a [2] 2f 40 [2] 38 4b [2] 23 05 [2] 1e }

  condition:
    any of them
}