rule TTP_XOR_MULT_DOSStub_6276 {
  strings:
    $key_6276 = { 36 1e [2] 42 06 [2] 05 04 [2] 42 15 [2] 0c 19 [2] 00 13 [2] 17 18 [2] 0c 56 [2] 31 }

  condition:
    any of them
}