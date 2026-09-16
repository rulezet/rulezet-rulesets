rule TTP_XOR_MULT_DOSStub_5351 {
  strings:
    $key_5351 = { 07 39 [2] 73 21 [2] 34 23 [2] 73 32 [2] 3d 3e [2] 31 34 [2] 26 3f [2] 3d 71 [2] 00 }

  condition:
    any of them
}