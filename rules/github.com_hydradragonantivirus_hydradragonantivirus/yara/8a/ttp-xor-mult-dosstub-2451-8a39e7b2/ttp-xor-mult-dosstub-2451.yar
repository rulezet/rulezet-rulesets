rule TTP_XOR_MULT_DOSStub_2451 {
  strings:
    $key_2451 = { 70 39 [2] 04 21 [2] 43 23 [2] 04 32 [2] 4a 3e [2] 46 34 [2] 51 3f [2] 4a 71 [2] 77 }

  condition:
    any of them
}