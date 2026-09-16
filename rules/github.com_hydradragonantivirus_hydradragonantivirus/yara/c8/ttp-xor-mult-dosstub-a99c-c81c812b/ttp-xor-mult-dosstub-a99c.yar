rule TTP_XOR_MULT_DOSStub_a99c {
  strings:
    $key_a99c = { fd f4 [2] 89 ec [2] ce ee [2] 89 ff [2] c7 f3 [2] cb f9 [2] dc f2 [2] c7 bc [2] fa }

  condition:
    any of them
}