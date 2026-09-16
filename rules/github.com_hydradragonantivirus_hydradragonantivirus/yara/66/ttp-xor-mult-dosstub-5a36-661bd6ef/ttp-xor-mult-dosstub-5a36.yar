rule TTP_XOR_MULT_DOSStub_5a36 {
  strings:
    $key_5a36 = { 0e 5e [2] 7a 46 [2] 3d 44 [2] 7a 55 [2] 34 59 [2] 38 53 [2] 2f 58 [2] 34 16 [2] 09 }

  condition:
    any of them
}