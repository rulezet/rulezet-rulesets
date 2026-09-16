rule TTP_XOR_MULT_DOSStub_a9e1 {
  strings:
    $key_a9e1 = { fd 89 [2] 89 91 [2] ce 93 [2] 89 82 [2] c7 8e [2] cb 84 [2] dc 8f [2] c7 c1 [2] fa }

  condition:
    any of them
}