rule TTP_XOR_MULT_DOSStub_1458 {
  strings:
    $key_1458 = { 40 30 [2] 34 28 [2] 73 2a [2] 34 3b [2] 7a 37 [2] 76 3d [2] 61 36 [2] 7a 78 [2] 47 }

  condition:
    any of them
}