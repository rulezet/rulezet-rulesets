rule TTP_XOR_MULT_DOSStub_3236 {
  strings:
    $key_3236 = { 66 5e [2] 12 46 [2] 55 44 [2] 12 55 [2] 5c 59 [2] 50 53 [2] 47 58 [2] 5c 16 [2] 61 }

  condition:
    any of them
}