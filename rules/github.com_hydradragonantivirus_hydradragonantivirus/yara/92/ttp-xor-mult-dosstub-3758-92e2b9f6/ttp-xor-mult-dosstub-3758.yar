rule TTP_XOR_MULT_DOSStub_3758 {
  strings:
    $key_3758 = { 63 30 [2] 17 28 [2] 50 2a [2] 17 3b [2] 59 37 [2] 55 3d [2] 42 36 [2] 59 78 [2] 64 }

  condition:
    any of them
}