rule TTP_XOR_MULT_DOSStub_6916 {
  strings:
    $key_6916 = { 3d 7e [2] 49 66 [2] 0e 64 [2] 49 75 [2] 07 79 [2] 0b 73 [2] 1c 78 [2] 07 36 [2] 3a }

  condition:
    any of them
}