rule TTP_XOR_MULT_DOSStub_5ba9 {
  strings:
    $key_5ba9 = { 0f c1 [2] 7b d9 [2] 3c db [2] 7b ca [2] 35 c6 [2] 39 cc [2] 2e c7 [2] 35 89 [2] 08 }

  condition:
    any of them
}