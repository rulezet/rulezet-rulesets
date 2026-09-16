rule TTP_XOR_MULT_DOSStub_5a01 {
  strings:
    $key_5a01 = { 0e 69 [2] 7a 71 [2] 3d 73 [2] 7a 62 [2] 34 6e [2] 38 64 [2] 2f 6f [2] 34 21 [2] 09 }

  condition:
    any of them
}