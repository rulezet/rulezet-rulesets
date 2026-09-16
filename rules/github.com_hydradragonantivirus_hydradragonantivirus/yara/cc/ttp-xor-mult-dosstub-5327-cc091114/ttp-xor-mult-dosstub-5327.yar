rule TTP_XOR_MULT_DOSStub_5327 {
  strings:
    $key_5327 = { 07 4f [2] 73 57 [2] 34 55 [2] 73 44 [2] 3d 48 [2] 31 42 [2] 26 49 [2] 3d 07 [2] 00 }

  condition:
    any of them
}