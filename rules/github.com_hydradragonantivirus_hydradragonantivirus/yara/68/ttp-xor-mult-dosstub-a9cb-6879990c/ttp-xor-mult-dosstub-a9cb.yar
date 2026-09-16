rule TTP_XOR_MULT_DOSStub_a9cb {
  strings:
    $key_a9cb = { fd a3 [2] 89 bb [2] ce b9 [2] 89 a8 [2] c7 a4 [2] cb ae [2] dc a5 [2] c7 eb [2] fa }

  condition:
    any of them
}