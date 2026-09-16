rule TTP_XOR_MULT_DOSStub_6aa8 {
  strings:
    $key_6aa8 = { 3e c0 [2] 4a d8 [2] 0d da [2] 4a cb [2] 04 c7 [2] 08 cd [2] 1f c6 [2] 04 88 [2] 39 }

  condition:
    any of them
}