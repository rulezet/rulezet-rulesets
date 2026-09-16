rule TTP_XOR_MULT_DOSStub_a9e7 {
  strings:
    $key_a9e7 = { fd 8f [2] 89 97 [2] ce 95 [2] 89 84 [2] c7 88 [2] cb 82 [2] dc 89 [2] c7 c7 [2] fa }

  condition:
    any of them
}