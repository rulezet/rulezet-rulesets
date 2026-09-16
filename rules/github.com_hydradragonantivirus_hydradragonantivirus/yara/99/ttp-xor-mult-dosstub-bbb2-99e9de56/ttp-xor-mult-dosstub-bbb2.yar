rule TTP_XOR_MULT_DOSStub_bbb2 {
  strings:
    $key_bbb2 = { ef da [2] 9b c2 [2] dc c0 [2] 9b d1 [2] d5 dd [2] d9 d7 [2] ce dc [2] d5 92 [2] e8 }

  condition:
    any of them
}