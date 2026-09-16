rule TTP_XOR_MULT_DOSStub_5058 {
  strings:
    $key_5058 = { 04 30 [2] 70 28 [2] 37 2a [2] 70 3b [2] 3e 37 [2] 32 3d [2] 25 36 [2] 3e 78 [2] 03 }

  condition:
    any of them
}