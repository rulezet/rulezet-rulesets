rule TTP_XOR_MULT_DOSStub_a9a9 {
  strings:
    $key_a9a9 = { fd c1 [2] 89 d9 [2] ce db [2] 89 ca [2] c7 c6 [2] cb cc [2] dc c7 [2] c7 89 [2] fa }

  condition:
    any of them
}