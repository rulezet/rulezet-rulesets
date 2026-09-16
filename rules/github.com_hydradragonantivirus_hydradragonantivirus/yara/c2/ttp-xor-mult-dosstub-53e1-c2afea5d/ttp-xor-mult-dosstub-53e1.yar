rule TTP_XOR_MULT_DOSStub_53e1 {
  strings:
    $key_53e1 = { 07 89 [2] 73 91 [2] 34 93 [2] 73 82 [2] 3d 8e [2] 31 84 [2] 26 8f [2] 3d c1 [2] 00 }

  condition:
    any of them
}