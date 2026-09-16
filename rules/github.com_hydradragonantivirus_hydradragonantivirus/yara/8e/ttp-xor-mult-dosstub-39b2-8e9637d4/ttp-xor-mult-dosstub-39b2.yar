rule TTP_XOR_MULT_DOSStub_39b2 {
  strings:
    $key_39b2 = { 6d da [2] 19 c2 [2] 5e c0 [2] 19 d1 [2] 57 dd [2] 5b d7 [2] 4c dc [2] 57 92 [2] 6a }

  condition:
    any of them
}