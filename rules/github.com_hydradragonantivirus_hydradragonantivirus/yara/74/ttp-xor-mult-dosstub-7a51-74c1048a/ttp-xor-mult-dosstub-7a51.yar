rule TTP_XOR_MULT_DOSStub_7a51 {
  strings:
    $key_7a51 = { 2e 39 [2] 5a 21 [2] 1d 23 [2] 5a 32 [2] 14 3e [2] 18 34 [2] 0f 3f [2] 14 71 [2] 29 }

  condition:
    any of them
}