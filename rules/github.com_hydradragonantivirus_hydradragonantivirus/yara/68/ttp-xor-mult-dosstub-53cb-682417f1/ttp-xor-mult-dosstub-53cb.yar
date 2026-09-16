rule TTP_XOR_MULT_DOSStub_53cb {
  strings:
    $key_53cb = { 07 a3 [2] 73 bb [2] 34 b9 [2] 73 a8 [2] 3d a4 [2] 31 ae [2] 26 a5 [2] 3d eb [2] 00 }

  condition:
    any of them
}