rule TTP_XOR_MULT_DOSStub_5321 {
  strings:
    $key_5321 = { 07 49 [2] 73 51 [2] 34 53 [2] 73 42 [2] 3d 4e [2] 31 44 [2] 26 4f [2] 3d 01 [2] 00 }

  condition:
    any of them
}