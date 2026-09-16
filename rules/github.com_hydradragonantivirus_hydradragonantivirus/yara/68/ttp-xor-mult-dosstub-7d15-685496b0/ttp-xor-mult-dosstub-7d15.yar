rule TTP_XOR_MULT_DOSStub_7d15 {
  strings:
    $key_7d15 = { 29 7d [2] 5d 65 [2] 1a 67 [2] 5d 76 [2] 13 7a [2] 1f 70 [2] 08 7b [2] 13 35 [2] 2e }

  condition:
    any of them
}