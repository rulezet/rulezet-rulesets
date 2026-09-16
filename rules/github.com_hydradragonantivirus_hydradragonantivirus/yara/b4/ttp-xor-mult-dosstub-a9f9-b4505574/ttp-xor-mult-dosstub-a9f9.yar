rule TTP_XOR_MULT_DOSStub_a9f9 {
  strings:
    $key_a9f9 = { fd 91 [2] 89 89 [2] ce 8b [2] 89 9a [2] c7 96 [2] cb 9c [2] dc 97 [2] c7 d9 [2] fa }

  condition:
    any of them
}