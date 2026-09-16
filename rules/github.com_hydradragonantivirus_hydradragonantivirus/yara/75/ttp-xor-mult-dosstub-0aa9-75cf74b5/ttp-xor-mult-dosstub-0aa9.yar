rule TTP_XOR_MULT_DOSStub_0aa9 {
  strings:
    $key_0aa9 = { 5e c1 [2] 2a d9 [2] 6d db [2] 2a ca [2] 64 c6 [2] 68 cc [2] 7f c7 [2] 64 89 [2] 59 }

  condition:
    any of them
}