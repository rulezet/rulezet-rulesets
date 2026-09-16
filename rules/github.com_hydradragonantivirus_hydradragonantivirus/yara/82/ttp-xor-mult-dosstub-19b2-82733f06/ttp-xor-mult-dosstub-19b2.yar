rule TTP_XOR_MULT_DOSStub_19b2 {
  strings:
    $key_19b2 = { 4d da [2] 39 c2 [2] 7e c0 [2] 39 d1 [2] 77 dd [2] 7b d7 [2] 6c dc [2] 77 92 [2] 4a }

  condition:
    any of them
}