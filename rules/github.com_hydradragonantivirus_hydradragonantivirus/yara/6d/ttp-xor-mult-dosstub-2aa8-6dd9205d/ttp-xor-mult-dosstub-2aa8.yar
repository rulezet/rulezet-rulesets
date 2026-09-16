rule TTP_XOR_MULT_DOSStub_2aa8 {
  strings:
    $key_2aa8 = { 7e c0 [2] 0a d8 [2] 4d da [2] 0a cb [2] 44 c7 [2] 48 cd [2] 5f c6 [2] 44 88 [2] 79 }

  condition:
    any of them
}