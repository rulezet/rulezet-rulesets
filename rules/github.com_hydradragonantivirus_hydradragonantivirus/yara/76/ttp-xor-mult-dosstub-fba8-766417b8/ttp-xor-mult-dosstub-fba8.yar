rule TTP_XOR_MULT_DOSStub_fba8 {
  strings:
    $key_fba8 = { af c0 [2] db d8 [2] 9c da [2] db cb [2] 95 c7 [2] 99 cd [2] 8e c6 [2] 95 88 [2] a8 }

  condition:
    any of them
}