rule TTP_XOR_MULT_DOSStub_7aa9 {
  strings:
    $key_7aa9 = { 2e c1 [2] 5a d9 [2] 1d db [2] 5a ca [2] 14 c6 [2] 18 cc [2] 0f c7 [2] 14 89 [2] 29 }

  condition:
    any of them
}