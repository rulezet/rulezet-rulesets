rule TTP_XOR_MULT_DOSStub_5aa9 {
  strings:
    $key_5aa9 = { 0e c1 [2] 7a d9 [2] 3d db [2] 7a ca [2] 34 c6 [2] 38 cc [2] 2f c7 [2] 34 89 [2] 09 }

  condition:
    any of them
}