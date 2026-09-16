rule TTP_XOR_MULT_DOSStub_4d07 {
  strings:
    $key_4d07 = { 19 6f [2] 6d 77 [2] 2a 75 [2] 6d 64 [2] 23 68 [2] 2f 62 [2] 38 69 [2] 23 27 [2] 1e }

  condition:
    any of them
}