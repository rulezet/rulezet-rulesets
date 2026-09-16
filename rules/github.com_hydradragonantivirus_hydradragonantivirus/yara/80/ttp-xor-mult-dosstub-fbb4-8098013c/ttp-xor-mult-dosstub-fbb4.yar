rule TTP_XOR_MULT_DOSStub_fbb4 {
  strings:
    $key_fbb4 = { af dc [2] db c4 [2] 9c c6 [2] db d7 [2] 95 db [2] 99 d1 [2] 8e da [2] 95 94 [2] a8 }

  condition:
    any of them
}