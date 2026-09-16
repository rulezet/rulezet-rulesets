rule TTP_XOR_MULT_DOSStub_3277 {
  strings:
    $key_3277 = { 66 1f [2] 12 07 [2] 55 05 [2] 12 14 [2] 5c 18 [2] 50 12 [2] 47 19 [2] 5c 57 [2] 61 }

  condition:
    any of them
}