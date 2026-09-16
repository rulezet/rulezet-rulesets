rule TTP_XOR_MULT_DOSStub_79b2 {
  strings:
    $key_79b2 = { 2d da [2] 59 c2 [2] 1e c0 [2] 59 d1 [2] 17 dd [2] 1b d7 [2] 0c dc [2] 17 92 [2] 2a }

  condition:
    any of them
}