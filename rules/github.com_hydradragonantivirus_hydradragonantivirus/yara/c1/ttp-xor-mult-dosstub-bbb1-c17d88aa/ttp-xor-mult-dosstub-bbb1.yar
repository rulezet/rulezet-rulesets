rule TTP_XOR_MULT_DOSStub_bbb1 {
  strings:
    $key_bbb1 = { ef d9 [2] 9b c1 [2] dc c3 [2] 9b d2 [2] d5 de [2] d9 d4 [2] ce df [2] d5 91 [2] e8 }

  condition:
    any of them
}