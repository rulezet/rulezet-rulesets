rule TTP_XOR_MULT_DOSStub_fbb3 {
  strings:
    $key_fbb3 = { af db [2] db c3 [2] 9c c1 [2] db d0 [2] 95 dc [2] 99 d6 [2] 8e dd [2] 95 93 [2] a8 }

  condition:
    any of them
}