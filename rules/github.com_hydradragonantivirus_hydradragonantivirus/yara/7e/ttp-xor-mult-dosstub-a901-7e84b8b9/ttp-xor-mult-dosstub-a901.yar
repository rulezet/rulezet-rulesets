rule TTP_XOR_MULT_DOSStub_a901 {
  strings:
    $key_a901 = { fd 69 [2] 89 71 [2] ce 73 [2] 89 62 [2] c7 6e [2] cb 64 [2] dc 6f [2] c7 21 [2] fa }

  condition:
    any of them
}