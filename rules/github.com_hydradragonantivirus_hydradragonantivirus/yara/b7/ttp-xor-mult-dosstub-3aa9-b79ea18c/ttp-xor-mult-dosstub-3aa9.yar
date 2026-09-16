rule TTP_XOR_MULT_DOSStub_3aa9 {
  strings:
    $key_3aa9 = { 6e c1 [2] 1a d9 [2] 5d db [2] 1a ca [2] 54 c6 [2] 58 cc [2] 4f c7 [2] 54 89 [2] 69 }

  condition:
    any of them
}