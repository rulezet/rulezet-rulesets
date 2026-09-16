rule TTP_XOR_MULT_DOSStub_5016 {
  strings:
    $key_5016 = { 04 7e [2] 70 66 [2] 37 64 [2] 70 75 [2] 3e 79 [2] 32 73 [2] 25 78 [2] 3e 36 [2] 03 }

  condition:
    any of them
}