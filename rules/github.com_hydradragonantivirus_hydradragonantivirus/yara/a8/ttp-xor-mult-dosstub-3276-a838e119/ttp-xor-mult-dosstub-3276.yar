rule TTP_XOR_MULT_DOSStub_3276 {
  strings:
    $key_3276 = { 66 1e [2] 12 06 [2] 55 04 [2] 12 15 [2] 5c 19 [2] 50 13 [2] 47 18 [2] 5c 56 [2] 61 }

  condition:
    any of them
}