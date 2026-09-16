rule TTP_XOR_MULT_DOSStub_4d31 {
  strings:
    $key_4d31 = { 19 59 [2] 6d 41 [2] 2a 43 [2] 6d 52 [2] 23 5e [2] 2f 54 [2] 38 5f [2] 23 11 [2] 1e }

  condition:
    any of them
}