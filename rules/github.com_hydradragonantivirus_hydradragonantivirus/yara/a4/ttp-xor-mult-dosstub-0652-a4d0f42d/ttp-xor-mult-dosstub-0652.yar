rule TTP_XOR_MULT_DOSStub_0652 {
  strings:
    $key_0652 = { 52 3a [2] 26 22 [2] 61 20 [2] 26 31 [2] 68 3d [2] 64 37 [2] 73 3c [2] 68 72 [2] 55 }

  condition:
    any of them
}