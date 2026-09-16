rule TTP_XOR_MULT_DOSStub_a927 {
  strings:
    $key_a927 = { fd 4f [2] 89 57 [2] ce 55 [2] 89 44 [2] c7 48 [2] cb 42 [2] dc 49 [2] c7 07 [2] fa }

  condition:
    any of them
}