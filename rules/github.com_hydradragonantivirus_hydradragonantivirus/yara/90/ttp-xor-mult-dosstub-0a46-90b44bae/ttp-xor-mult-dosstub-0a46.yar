rule TTP_XOR_MULT_DOSStub_0a46 {
  strings:
    $key_0a46 = { 5e 2e [2] 2a 36 [2] 6d 34 [2] 2a 25 [2] 64 29 [2] 68 23 [2] 7f 28 [2] 64 66 [2] 59 }

  condition:
    any of them
}