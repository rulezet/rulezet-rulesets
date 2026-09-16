rule TTP_XOR_MULT_DOSStub_2476 {
  strings:
    $key_2476 = { 70 1e [2] 04 06 [2] 43 04 [2] 04 15 [2] 4a 19 [2] 46 13 [2] 51 18 [2] 4a 56 [2] 77 }

  condition:
    any of them
}