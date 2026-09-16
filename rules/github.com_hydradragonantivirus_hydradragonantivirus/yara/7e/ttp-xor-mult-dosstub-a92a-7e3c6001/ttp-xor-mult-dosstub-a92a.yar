rule TTP_XOR_MULT_DOSStub_a92a {
  strings:
    $key_a92a = { fd 42 [2] 89 5a [2] ce 58 [2] 89 49 [2] c7 45 [2] cb 4f [2] dc 44 [2] c7 0a [2] fa }

  condition:
    any of them
}