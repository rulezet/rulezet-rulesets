rule TTP_XOR_MULT_DOSStub_a9f8 {
  strings:
    $key_a9f8 = { fd 90 [2] 89 88 [2] ce 8a [2] 89 9b [2] c7 97 [2] cb 9d [2] dc 96 [2] c7 d8 [2] fa }

  condition:
    any of them
}