rule TTP_XOR_MULT_DOSStub_a9ca {
  strings:
    $key_a9ca = { fd a2 [2] 89 ba [2] ce b8 [2] 89 a9 [2] c7 a5 [2] cb af [2] dc a4 [2] c7 ea [2] fa }

  condition:
    any of them
}