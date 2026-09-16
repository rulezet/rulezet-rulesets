rule TTP_XOR_MULT_DOSStub_faa8 {
  strings:
    $key_faa8 = { ae c0 [2] da d8 [2] 9d da [2] da cb [2] 94 c7 [2] 98 cd [2] 8f c6 [2] 94 88 [2] a9 }

  condition:
    any of them
}