rule TTP_XOR_MULT_DOSStub_0310 {
  strings:
    $key_0310 = { 57 78 [2] 23 60 [2] 64 62 [2] 23 73 [2] 6d 7f [2] 61 75 [2] 76 7e [2] 6d 30 [2] 50 }

  condition:
    any of them
}