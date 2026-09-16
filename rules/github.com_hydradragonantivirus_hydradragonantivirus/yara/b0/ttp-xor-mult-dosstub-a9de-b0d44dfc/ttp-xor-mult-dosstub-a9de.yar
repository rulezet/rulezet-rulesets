rule TTP_XOR_MULT_DOSStub_a9de {
  strings:
    $key_a9de = { fd b6 [2] 89 ae [2] ce ac [2] 89 bd [2] c7 b1 [2] cb bb [2] dc b0 [2] c7 fe [2] fa }

  condition:
    any of them
}