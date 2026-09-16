rule TTP_XOR_MULT_DOSStub_4a16 {
  strings:
    $key_4a16 = { 1e 7e [2] 6a 66 [2] 2d 64 [2] 6a 75 [2] 24 79 [2] 28 73 [2] 3f 78 [2] 24 36 [2] 19 }

  condition:
    any of them
}