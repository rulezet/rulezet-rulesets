rule TTP_XOR_MULT_DOSStub_3977 {
  strings:
    $key_3977 = { 6d 1f [2] 19 07 [2] 5e 05 [2] 19 14 [2] 57 18 [2] 5b 12 [2] 4c 19 [2] 57 57 [2] 6a }

  condition:
    any of them
}