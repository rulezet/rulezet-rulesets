rule TTP_XOR_MULT_DOSStub_acb8 {
  strings:
    $key_acb8 = { f8 d0 [2] 8c c8 [2] cb ca [2] 8c db [2] c2 d7 [2] ce dd [2] d9 d6 [2] c2 98 [2] ff }

  condition:
    any of them
}