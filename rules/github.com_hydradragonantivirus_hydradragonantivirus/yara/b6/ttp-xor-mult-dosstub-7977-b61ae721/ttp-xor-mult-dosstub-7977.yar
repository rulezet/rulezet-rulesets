rule TTP_XOR_MULT_DOSStub_7977 {
  strings:
    $key_7977 = { 2d 1f [2] 59 07 [2] 1e 05 [2] 59 14 [2] 17 18 [2] 1b 12 [2] 0c 19 [2] 17 57 [2] 2a }

  condition:
    any of them
}