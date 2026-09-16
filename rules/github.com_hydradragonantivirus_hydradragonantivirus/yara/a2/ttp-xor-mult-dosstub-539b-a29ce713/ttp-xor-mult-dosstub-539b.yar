rule TTP_XOR_MULT_DOSStub_539b {
  strings:
    $key_539b = { 07 f3 [2] 73 eb [2] 34 e9 [2] 73 f8 [2] 3d f4 [2] 31 fe [2] 26 f5 [2] 3d bb [2] 00 }

  condition:
    any of them
}