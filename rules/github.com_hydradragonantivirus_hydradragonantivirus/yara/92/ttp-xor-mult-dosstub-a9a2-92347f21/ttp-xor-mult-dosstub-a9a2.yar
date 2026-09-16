rule TTP_XOR_MULT_DOSStub_a9a2 {
  strings:
    $key_a9a2 = { fd ca [2] 89 d2 [2] ce d0 [2] 89 c1 [2] c7 cd [2] cb c7 [2] dc cc [2] c7 82 [2] fa }

  condition:
    any of them
}