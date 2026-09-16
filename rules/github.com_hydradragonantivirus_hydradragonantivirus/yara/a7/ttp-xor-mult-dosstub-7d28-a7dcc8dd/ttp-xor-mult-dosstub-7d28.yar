rule TTP_XOR_MULT_DOSStub_7d28 {
  strings:
    $key_7d28 = { 29 40 [2] 5d 58 [2] 1a 5a [2] 5d 4b [2] 13 47 [2] 1f 4d [2] 08 46 [2] 13 08 [2] 2e }

  condition:
    any of them
}