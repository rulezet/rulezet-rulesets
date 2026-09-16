rule TTP_XOR_MULT_DOSStub_5a40 {
  strings:
    $key_5a40 = { 0e 28 [2] 7a 30 [2] 3d 32 [2] 7a 23 [2] 34 2f [2] 38 25 [2] 2f 2e [2] 34 60 [2] 09 }

  condition:
    any of them
}