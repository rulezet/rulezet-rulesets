rule TTP_XOR_MULT_DOSStub_3ba9 {
  strings:
    $key_3ba9 = { 6f c1 [2] 1b d9 [2] 5c db [2] 1b ca [2] 55 c6 [2] 59 cc [2] 4e c7 [2] 55 89 [2] 68 }

  condition:
    any of them
}