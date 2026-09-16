rule TTP_XOR_MULT_DOSStub_0350 {
  strings:
    $key_0350 = { 57 38 [2] 23 20 [2] 64 22 [2] 23 33 [2] 6d 3f [2] 61 35 [2] 76 3e [2] 6d 70 [2] 50 }

  condition:
    any of them
}