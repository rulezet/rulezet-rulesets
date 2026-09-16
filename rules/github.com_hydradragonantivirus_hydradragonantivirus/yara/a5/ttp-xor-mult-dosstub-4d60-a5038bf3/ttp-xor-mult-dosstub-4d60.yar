rule TTP_XOR_MULT_DOSStub_4d60 {
  strings:
    $key_4d60 = { 19 08 [2] 6d 10 [2] 2a 12 [2] 6d 03 [2] 23 0f [2] 2f 05 [2] 38 0e [2] 23 40 [2] 1e }

  condition:
    any of them
}