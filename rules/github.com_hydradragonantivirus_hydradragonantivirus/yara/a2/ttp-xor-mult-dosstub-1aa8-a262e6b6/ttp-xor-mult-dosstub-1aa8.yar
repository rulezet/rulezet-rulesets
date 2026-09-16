rule TTP_XOR_MULT_DOSStub_1aa8 {
  strings:
    $key_1aa8 = { 4e c0 [2] 3a d8 [2] 7d da [2] 3a cb [2] 74 c7 [2] 78 cd [2] 6f c6 [2] 74 88 [2] 49 }

  condition:
    any of them
}