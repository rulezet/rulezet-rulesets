rule TTP_XOR_MULT_DOSStub_a9e0 {
  strings:
    $key_a9e0 = { fd 88 [2] 89 90 [2] ce 92 [2] 89 83 [2] c7 8f [2] cb 85 [2] dc 8e [2] c7 c0 [2] fa }

  condition:
    any of them
}