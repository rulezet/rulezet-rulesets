rule TTP_XOR_MULT_DOSStub_a931 {
  strings:
    $key_a931 = { fd 59 [2] 89 41 [2] ce 43 [2] 89 52 [2] c7 5e [2] cb 54 [2] dc 5f [2] c7 11 [2] fa }

  condition:
    any of them
}