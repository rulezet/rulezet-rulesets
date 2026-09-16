rule TTP_XOR_MULT_DOSStub_5a41 {
  strings:
    $key_5a41 = { 0e 29 [2] 7a 31 [2] 3d 33 [2] 7a 22 [2] 34 2e [2] 38 24 [2] 2f 2f [2] 34 61 [2] 09 }

  condition:
    any of them
}