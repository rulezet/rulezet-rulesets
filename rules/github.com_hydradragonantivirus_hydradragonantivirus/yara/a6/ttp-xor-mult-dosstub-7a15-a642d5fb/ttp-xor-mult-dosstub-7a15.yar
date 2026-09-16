rule TTP_XOR_MULT_DOSStub_7a15 {
  strings:
    $key_7a15 = { 2e 7d [2] 5a 65 [2] 1d 67 [2] 5a 76 [2] 14 7a [2] 18 70 [2] 0f 7b [2] 14 35 [2] 29 }

  condition:
    any of them
}