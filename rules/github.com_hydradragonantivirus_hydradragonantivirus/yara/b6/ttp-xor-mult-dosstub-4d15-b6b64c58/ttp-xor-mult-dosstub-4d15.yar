rule TTP_XOR_MULT_DOSStub_4d15 {
  strings:
    $key_4d15 = { 19 7d [2] 6d 65 [2] 2a 67 [2] 6d 76 [2] 23 7a [2] 2f 70 [2] 38 7b [2] 23 35 [2] 1e }

  condition:
    any of them
}