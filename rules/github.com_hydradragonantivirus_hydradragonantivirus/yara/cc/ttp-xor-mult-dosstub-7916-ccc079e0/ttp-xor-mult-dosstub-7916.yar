rule TTP_XOR_MULT_DOSStub_7916 {
  strings:
    $key_7916 = { 2d 7e [2] 59 66 [2] 1e 64 [2] 59 75 [2] 17 79 [2] 1b 73 [2] 0c 78 [2] 17 36 [2] 2a }

  condition:
    any of them
}