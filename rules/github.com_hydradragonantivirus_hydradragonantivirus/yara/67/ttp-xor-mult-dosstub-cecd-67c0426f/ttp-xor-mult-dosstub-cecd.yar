rule TTP_XOR_MULT_DOSStub_cecd {
  strings:
    $key_cecd = { 9a a5 [2] ee bd [2] a9 bf [2] ee ae [2] a0 a2 [2] ac a8 [2] bb a3 [2] a0 ed [2] 9d }

  condition:
    any of them
}