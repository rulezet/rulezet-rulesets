rule TTP_XOR_MULT_DOSStub_7d33 {
  strings:
    $key_7d33 = { 29 5b [2] 5d 43 [2] 1a 41 [2] 5d 50 [2] 13 5c [2] 1f 56 [2] 08 5d [2] 13 13 [2] 2e }

  condition:
    any of them
}