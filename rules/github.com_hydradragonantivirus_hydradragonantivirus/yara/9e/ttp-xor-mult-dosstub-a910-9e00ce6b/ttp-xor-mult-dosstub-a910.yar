rule TTP_XOR_MULT_DOSStub_a910 {
  strings:
    $key_a910 = { fd 78 [2] 89 60 [2] ce 62 [2] 89 73 [2] c7 7f [2] cb 75 [2] dc 7e [2] c7 30 [2] fa }

  condition:
    any of them
}