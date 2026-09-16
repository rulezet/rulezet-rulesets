rule TTP_XOR_MULT_DOSStub_4331 {
  strings:
    $key_4331 = { 17 59 [2] 63 41 [2] 24 43 [2] 63 52 [2] 2d 5e [2] 21 54 [2] 36 5f [2] 2d 11 [2] 10 }

  condition:
    any of them
}