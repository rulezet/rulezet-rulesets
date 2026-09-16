rule TTP_XOR_MULT_DOSStub_3aa8 {
  strings:
    $key_3aa8 = { 6e c0 [2] 1a d8 [2] 5d da [2] 1a cb [2] 54 c7 [2] 58 cd [2] 4f c6 [2] 54 88 [2] 69 }

  condition:
    any of them
}