rule TTP_XOR_MULT_DOSStub_5320 {
  strings:
    $key_5320 = { 07 48 [2] 73 50 [2] 34 52 [2] 73 43 [2] 3d 4f [2] 31 45 [2] 26 4e [2] 3d 00 [2] 00 }

  condition:
    any of them
}