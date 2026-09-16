rule TTP_XOR_MULT_DOSStub_a921 {
  strings:
    $key_a921 = { fd 49 [2] 89 51 [2] ce 53 [2] 89 42 [2] c7 4e [2] cb 44 [2] dc 4f [2] c7 01 [2] fa }

  condition:
    any of them
}