rule TTP_XOR_MULT_DOSStub_5a16 {
  strings:
    $key_5a16 = { 0e 7e [2] 7a 66 [2] 3d 64 [2] 7a 75 [2] 34 79 [2] 38 73 [2] 2f 78 [2] 34 36 [2] 09 }

  condition:
    any of them
}