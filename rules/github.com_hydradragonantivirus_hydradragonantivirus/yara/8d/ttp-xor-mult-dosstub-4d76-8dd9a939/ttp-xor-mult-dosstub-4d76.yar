rule TTP_XOR_MULT_DOSStub_4d76 {
  strings:
    $key_4d76 = { 19 1e [2] 6d 06 [2] 2a 04 [2] 6d 15 [2] 23 19 [2] 2f 13 [2] 38 18 [2] 23 56 [2] 1e }

  condition:
    any of them
}