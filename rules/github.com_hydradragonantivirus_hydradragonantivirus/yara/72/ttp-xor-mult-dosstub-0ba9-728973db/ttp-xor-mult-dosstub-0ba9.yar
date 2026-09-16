rule TTP_XOR_MULT_DOSStub_0ba9 {
  strings:
    $key_0ba9 = { 5f c1 [2] 2b d9 [2] 6c db [2] 2b ca [2] 65 c6 [2] 69 cc [2] 7e c7 [2] 65 89 [2] 58 }

  condition:
    any of them
}