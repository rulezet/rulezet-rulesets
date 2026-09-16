rule TTP_XOR_MULT_DOSStub_48a4 {
  strings:
    $key_48a4 = { 1c cc [2] 68 d4 [2] 2f d6 [2] 68 c7 [2] 26 cb [2] 2a c1 [2] 3d ca [2] 26 84 [2] 1b }

  condition:
    any of them
}