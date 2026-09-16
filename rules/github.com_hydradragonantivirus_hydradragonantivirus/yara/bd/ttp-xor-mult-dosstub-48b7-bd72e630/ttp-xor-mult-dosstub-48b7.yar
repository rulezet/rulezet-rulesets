rule TTP_XOR_MULT_DOSStub_48b7 {
  strings:
    $key_48b7 = { 1c df [2] 68 c7 [2] 2f c5 [2] 68 d4 [2] 26 d8 [2] 2a d2 [2] 3d d9 [2] 26 97 [2] 1b }

  condition:
    any of them
}