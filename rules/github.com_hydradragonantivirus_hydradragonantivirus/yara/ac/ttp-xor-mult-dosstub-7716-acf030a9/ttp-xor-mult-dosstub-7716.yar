rule TTP_XOR_MULT_DOSStub_7716 {
  strings:
    $key_7716 = { 23 7e [2] 57 66 [2] 10 64 [2] 57 75 [2] 19 79 [2] 15 73 [2] 02 78 [2] 19 36 [2] 24 }

  condition:
    any of them
}