rule TTP_XOR_MULT_DOSStub_6216 {
  strings:
    $key_6216 = { 36 7e [2] 42 66 [2] 05 64 [2] 42 75 [2] 0c 79 [2] 00 73 [2] 17 78 [2] 0c 36 [2] 31 }

  condition:
    any of them
}