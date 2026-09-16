rule TTP_XOR_MULT_DOSStub_4aa9 {
  strings:
    $key_4aa9 = { 1e c1 [2] 6a d9 [2] 2d db [2] 6a ca [2] 24 c6 [2] 28 cc [2] 3f c7 [2] 24 89 [2] 19 }

  condition:
    any of them
}