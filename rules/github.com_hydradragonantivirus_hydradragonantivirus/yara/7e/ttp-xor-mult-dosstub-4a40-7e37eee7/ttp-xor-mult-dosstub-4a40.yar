rule TTP_XOR_MULT_DOSStub_4a40 {
  strings:
    $key_4a40 = { 1e 28 [2] 6a 30 [2] 2d 32 [2] 6a 23 [2] 24 2f [2] 28 25 [2] 3f 2e [2] 24 60 [2] 19 }

  condition:
    any of them
}