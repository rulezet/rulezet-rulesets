rule TTP_XOR_MULT_DOSStub_7d35 {
  strings:
    $key_7d35 = { 29 5d [2] 5d 45 [2] 1a 47 [2] 5d 56 [2] 13 5a [2] 1f 50 [2] 08 5b [2] 13 15 [2] 2e }

  condition:
    any of them
}