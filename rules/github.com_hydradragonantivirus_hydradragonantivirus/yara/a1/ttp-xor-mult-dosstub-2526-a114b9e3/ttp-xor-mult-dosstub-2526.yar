rule TTP_XOR_MULT_DOSStub_2526 {
  strings:
    $key_2526 = { 71 4e [2] 05 56 [2] 42 54 [2] 05 45 [2] 4b 49 [2] 47 43 [2] 50 48 [2] 4b 06 [2] 76 }

  condition:
    any of them
}