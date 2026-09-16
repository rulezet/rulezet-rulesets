rule TTP_XOR_MULT_DOSStub_4a51 {
  strings:
    $key_4a51 = { 1e 39 [2] 6a 21 [2] 2d 23 [2] 6a 32 [2] 24 3e [2] 28 34 [2] 3f 3f [2] 24 71 [2] 19 }

  condition:
    any of them
}