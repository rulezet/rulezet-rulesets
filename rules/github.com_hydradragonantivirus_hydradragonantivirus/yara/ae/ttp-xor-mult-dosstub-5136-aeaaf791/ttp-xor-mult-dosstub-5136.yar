rule TTP_XOR_MULT_DOSStub_5136 {
  strings:
    $key_5136 = { 05 5e [2] 71 46 [2] 36 44 [2] 71 55 [2] 3f 59 [2] 33 53 [2] 24 58 [2] 3f 16 [2] 02 }

  condition:
    any of them
}